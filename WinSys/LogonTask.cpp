#include "pch.h"
#include "LogonTask.h"
#include <taskschd.h>
#include <wil/com.h>
#include <wil/resource.h>
#define SECURITY_WIN32
#include <security.h>

#pragma comment(lib, "taskschd")
#pragma comment(lib, "secur32")

using namespace WinSys;

namespace {
	bool Fail(HRESULT hr) {
		::SetLastError(HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : (DWORD)hr);
		return false;
	}

	struct Scheduler {
		wil::com_ptr_nothrow<ITaskService> Service;
		wil::com_ptr_nothrow<ITaskFolder> Root;

		HRESULT Open() {
			auto hr = ::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&Service));
			if (FAILED(hr))
				return hr;
			VARIANT empty{};
			hr = Service->Connect(empty, empty, empty, empty);
			if (FAILED(hr))
				return hr;
			wil::unique_bstr root(::SysAllocString(L"\\"));
			return Service->GetFolder(root.get(), &Root);
		}
	};

	// DOMAIN\user, as the principal and the logon trigger take it
	std::wstring CurrentUser() {
		WCHAR name[256];
		ULONG size = _countof(name);
		return ::GetUserNameEx(NameSamCompatible, name, &size) ? name : L"";
	}

	wil::unique_bstr Bstr(std::wstring const& text) {
		return wil::unique_bstr(::SysAllocString(text.c_str()));
	}
}

bool LogonTask::Register(std::wstring const& name, std::wstring const& path, std::wstring const& arguments, bool highest,
	std::wstring const& description) {
	Scheduler scheduler;
	auto hr = scheduler.Open();
	if (FAILED(hr))
		return Fail(hr);
	auto user = CurrentUser();
	if (user.empty())
		return false;

	wil::com_ptr_nothrow<ITaskDefinition> task;
	if (FAILED(hr = scheduler.Service->NewTask(0, &task)))
		return Fail(hr);

	wil::com_ptr_nothrow<IRegistrationInfo> info;
	if (SUCCEEDED(task->get_RegistrationInfo(&info))) {
		info->put_Author(Bstr(user).get());
		if (!description.empty())
			info->put_Description(Bstr(description).get());
	}

	wil::com_ptr_nothrow<IPrincipal> principal;
	if (FAILED(hr = task->get_Principal(&principal)))
		return Fail(hr);
	principal->put_UserId(Bstr(user).get());
	principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
	principal->put_RunLevel(highest ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA);

	wil::com_ptr_nothrow<ITaskSettings> settings;
	if (FAILED(hr = task->get_Settings(&settings)))
		return Fail(hr);
	settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
	settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
	settings->put_ExecutionTimeLimit(Bstr(L"PT0S").get());
	settings->put_Priority(4);

	wil::com_ptr_nothrow<ITriggerCollection> triggers;
	wil::com_ptr_nothrow<ITrigger> trigger;
	if (FAILED(hr = task->get_Triggers(&triggers)) || FAILED(hr = triggers->Create(TASK_TRIGGER_LOGON, &trigger)))
		return Fail(hr);
	auto logon = trigger.try_query<ILogonTrigger>();
	if (!logon)
		return Fail(E_NOINTERFACE);
	logon->put_UserId(Bstr(user).get());

	wil::com_ptr_nothrow<IActionCollection> actions;
	wil::com_ptr_nothrow<IAction> action;
	if (FAILED(hr = task->get_Actions(&actions)) || FAILED(hr = actions->Create(TASK_ACTION_EXEC, &action)))
		return Fail(hr);
	auto exec = action.try_query<IExecAction>();
	if (!exec)
		return Fail(E_NOINTERFACE);
	exec->put_Path(Bstr(path).get());
	exec->put_Arguments(Bstr(arguments).get());
	auto slash = path.rfind(L'\\');
	if (slash != std::wstring::npos)
		exec->put_WorkingDirectory(Bstr(path.substr(0, slash)).get());

	VARIANT empty{};
	wil::com_ptr_nothrow<IRegisteredTask> registered;
	hr = scheduler.Root->RegisterTaskDefinition(Bstr(name).get(), task.get(), TASK_CREATE_OR_UPDATE, empty, empty,
		TASK_LOGON_INTERACTIVE_TOKEN, empty, &registered);
	return SUCCEEDED(hr) ? true : Fail(hr);
}

bool LogonTask::Delete(std::wstring const& name) {
	Scheduler scheduler;
	auto hr = scheduler.Open();
	if (SUCCEEDED(hr))
		hr = scheduler.Root->DeleteTask(Bstr(name).get(), 0);
	return SUCCEEDED(hr) ? true : Fail(hr);
}

std::optional<LogonTaskAction> LogonTask::GetAction(std::wstring const& name) {
	Scheduler scheduler;
	auto hr = scheduler.Open();
	wil::com_ptr_nothrow<IRegisteredTask> task;
	wil::com_ptr_nothrow<ITaskDefinition> definition;
	wil::com_ptr_nothrow<IActionCollection> actions;
	wil::com_ptr_nothrow<IAction> action;
	if (FAILED(hr) || FAILED(hr = scheduler.Root->GetTask(Bstr(name).get(), &task)) || FAILED(hr = task->get_Definition(&definition))
		|| FAILED(hr = definition->get_Actions(&actions)) || FAILED(hr = actions->get_Item(1, &action))) {
		Fail(hr);
		return std::nullopt;
	}
	auto exec = action.try_query<IExecAction>();
	if (!exec) {
		Fail(E_NOINTERFACE);
		return std::nullopt;
	}
	LogonTaskAction result;
	wil::unique_bstr text;
	if (SUCCEEDED(exec->get_Path(&text)) && text)
		result.Path = text.get();
	text.reset();
	if (SUCCEEDED(exec->get_Arguments(&text)) && text)
		result.Arguments = text.get();
	return result;
}
