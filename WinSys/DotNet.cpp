#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include "DotNet.h"
#include "EtwSession.h"
#include <wil/resource.h>
#include <algorithm>

using namespace WinSys;

bool DotNetInfo::HasFrameworkRuntime(uint32_t pid, uint32_t sessionId) {
	for (auto name : { L"Cor_Private_IPCBlock_v4_", L"Cor_Private_IPCBlock_" }) {
		auto path = (sessionId == 0 ? std::wstring(L"\\BaseNamedObjects\\")
			: L"\\Sessions\\" + std::to_wstring(sessionId) + L"\\BaseNamedObjects\\") + name + std::to_wstring(pid);
		UNICODE_STRING uname;
		::RtlInitUnicodeString(&uname, path.c_str());
		OBJECT_ATTRIBUTES attr;
		InitializeObjectAttributes(&attr, &uname, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		HANDLE hSection;
		auto status = ::NtOpenSection(&hSection, SECTION_QUERY, &attr);
		if (NT_SUCCESS(status))
			::NtClose(hSection);
		// another user's section exists even if it can't be opened
		if (NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED)
			return true;
	}
	return false;
}

std::unordered_set<uint32_t> DotNetInfo::GetCoreRuntimeProcesses() {
	std::unordered_set<uint32_t> pids;
	const std::wstring_view prefix = L"dotnet-diagnostic-";
	WIN32_FIND_DATA fd;
	wil::unique_hfind hFind(::FindFirstFile(L"\\\\.\\pipe\\*", &fd));
	if (!hFind)
		return pids;
	do {
		if (std::wstring_view(fd.cFileName).starts_with(prefix))
			if (auto pid = ::wcstoul(fd.cFileName + prefix.size(), nullptr, 10))
				pids.insert(pid);
	} while (::FindNextFile(hFind.get(), &fd));
	return pids;
}

bool DotNetInfo::HasRuntimeModule(uint32_t pid) {
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
	if (!hProcess)
		return false;
	std::vector<HMODULE> modules(512);
	DWORD needed = 0;
	for (;;) {
		if (!::EnumProcessModulesEx(hProcess.get(), modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL))
			return false;
		if (needed <= modules.size() * sizeof(HMODULE))
			break;
		modules.resize(needed / sizeof(HMODULE) + 64);
	}
	modules.resize(needed / sizeof(HMODULE));
	for (auto hModule : modules) {
		WCHAR name[MAX_PATH];
		if (::GetModuleBaseNameW(hProcess.get(), hModule, name, _countof(name))
			&& (_wcsicmp(name, L"clr.dll") == 0 || _wcsicmp(name, L"coreclr.dll") == 0 || _wcsicmp(name, L"mscorwks.dll") == 0))
			return true;
	}
	return false;
}

namespace {
	// Microsoft-Windows-DotNETRuntimeRundown
	const GUID RundownProvider = { 0xA669021C, 0xC450, 0x4609, { 0xA0, 0x35, 0x5A, 0xF5, 0x9A, 0xF4, 0xDF, 0x18 } };
	const ULONGLONG LoaderRundownKeyword = 0x8, StartRundownKeyword = 0x40;

	enum RundownEvent : USHORT {
		DCStartComplete = 145, ModuleDCStart = 153, AssemblyDCStart = 155, AppDomainDCStart = 157, RuntimeInformationDCStart = 187,
	};

	// reads an event's payload in order; a read past its end makes Ok false (and gives zeros)
	struct PayloadReader {
		BYTE const* Pos, * End;
		bool Ok{ true };

		template<typename T>
		T Get() {
			T value{};
			if (End - Pos < (ptrdiff_t)sizeof(T)) {
				Ok = false;
				Pos = End;
				return value;
			}
			memcpy(&value, Pos, sizeof(T));
			Pos += sizeof(T);
			return value;
		}

		std::wstring String() {
			auto start = reinterpret_cast<WCHAR const*>(Pos);
			auto count = (End - Pos) / (ptrdiff_t)sizeof(WCHAR);
			for (ptrdiff_t i = 0; i < count; i++) {
				if (start[i] == 0) {
					Pos += (i + 1) * sizeof(WCHAR);
					return std::wstring(start, i);
				}
			}
			Ok = false;
			Pos = End;
			return L"";
		}
	};

	struct RundownContext {
		uint32_t Pid;
		DotNetProcessDetails Details;
		std::vector<uint16_t> Completed;	// the runtimes (CLR instance IDs) whose rundown is done
		HANDLE hDone;
	};

	std::wstring VersionText(uint16_t major, uint16_t minor, uint16_t build, uint16_t qfe) {
		return std::to_wstring(major) + L"." + std::to_wstring(minor) + L"." + std::to_wstring(build) + L"." + std::to_wstring(qfe);
	}

	void WINAPI OnRundownEvent(PEVENT_RECORD record) {
		auto& context = *static_cast<RundownContext*>(record->UserContext);
		if (record->EventHeader.ProviderId != RundownProvider || record->EventHeader.ProcessId != context.Pid)
			return;
		auto data = static_cast<BYTE const*>(record->UserData);
		PayloadReader r{ data, data + record->UserDataLength };
		auto version = record->EventHeader.EventDescriptor.Version;
		auto& details = context.Details;
		switch (record->EventHeader.EventDescriptor.Id) {
			case RuntimeInformationDCStart:
			{
				DotNetRuntime rt;
				rt.ClrInstanceId = r.Get<uint16_t>();
				rt.Core = r.Get<uint16_t>() == 2;	// Sku: 1 the desktop CLR, 2 CoreCLR
				uint16_t v[8];
				for (auto& n : v)
					n = r.Get<uint16_t>();
				rt.BclVersion = VersionText(v[0], v[1], v[2], v[3]);
				rt.Version = VersionText(v[4], v[5], v[6], v[7]);
				rt.StartupFlags = r.Get<uint32_t>();
				r.Get<uint8_t>();	// StartupMode
				rt.CommandLine = r.String();
				r.Get<GUID>();	// ComObjectGuid
				rt.RuntimePath = r.String();
				if (r.Ok)
					details.Runtimes.push_back(std::move(rt));
				break;
			}
			case AppDomainDCStart:
			{
				DotNetAppDomain d;
				d.Id = r.Get<uint64_t>();
				d.Flags = r.Get<uint32_t>();
				d.Name = r.String();
				if (version >= 1)
					d.Index = r.Get<uint32_t>();
				if (r.Ok)
					details.AppDomains.push_back(std::move(d));
				break;
			}
			case AssemblyDCStart:
			{
				DotNetAssembly a;
				a.Id = r.Get<uint64_t>();
				a.AppDomainId = r.Get<uint64_t>();
				if (version >= 1)
					r.Get<uint64_t>();	// BindingID
				a.Flags = r.Get<uint32_t>();
				a.FullName = r.String();
				if (r.Ok)
					details.Assemblies.push_back(std::move(a));
				break;
			}
			case ModuleDCStart:
			{
				DotNetModule m;
				m.Id = r.Get<uint64_t>();
				m.AssemblyId = r.Get<uint64_t>();
				m.Flags = r.Get<uint32_t>();
				r.Get<uint32_t>();	// Reserved1
				m.ILPath = r.String();
				m.NativePath = r.String();
				if (r.Ok)
					details.Modules.push_back(std::move(m));
				break;
			}
			case DCStartComplete:
			{
				// version 0 has no payload: the only runtime
				auto instance = version >= 1 ? r.Get<uint16_t>() : (uint16_t)0;
				context.Completed.push_back(instance);
				// done when every runtime that said it's there is (the runtime information comes first)
				bool all = version == 0 || std::all_of(details.Runtimes.begin(), details.Runtimes.end(), [&](auto& rt) {
					return std::find(context.Completed.begin(), context.Completed.end(), rt.ClrInstanceId) != context.Completed.end();
					});
				if (all) {
					details.Complete = true;
					::SetEvent(context.hDone);
				}
				break;
			}
		}
	}

	DWORD WINAPI RundownThread(void* param) {
		auto trace = *static_cast<PROCESSTRACE_HANDLE*>(param);
		return ::ProcessTrace(&trace, 1, nullptr, nullptr);
	}
}

std::optional<DotNetProcessDetails> DotNetInfo::QueryProcess(uint32_t pid, PCWSTR sessionPrefix, uint32_t timeoutMs, HANDLE hCancel) {
	static LONG s_Sequence;
	std::wstring prefix(sessionPrefix);
	Etw::StopOrphanedSessions(prefix);
	// unique in the process, so that two queries can run at once ("<prefix><pid>" is what StopOrphanedSessions reads)
	auto name = prefix + std::to_wstring(::GetCurrentProcessId()) + L"." + std::to_wstring(::InterlockedIncrement(&s_Sequence));

	TRACEHANDLE session = 0;
	auto props = Etw::MakeProperties();
	auto error = ::StartTrace(&session, name.c_str(), &props.Properties);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return std::nullopt;
	}

	RundownContext context{ pid };
	wil::unique_handle hDone(::CreateEvent(nullptr, TRUE, FALSE, nullptr));
	context.hDone = hDone.get();

	// the consumer first, so that no event is lost
	EVENT_TRACE_LOGFILE log{};
	log.LoggerName = name.data();
	log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	log.EventRecordCallback = OnRundownEvent;
	log.Context = &context;
	PROCESSTRACE_HANDLE trace = ::OpenTrace(&log);
	wil::unique_handle hThread;
	if (trace == INVALID_PROCESSTRACE_HANDLE)
		error = ::GetLastError();
	else {
		hThread.reset(::CreateThread(nullptr, 0, RundownThread, &trace, 0, nullptr));
		if (!hThread)
			error = ::GetLastError();
	}

	if (error == ERROR_SUCCESS) {
		// only the process's runtime is told about the session, so only it runs down
		ULONG pids[] = { pid };
		EVENT_FILTER_DESCRIPTOR filter{};
		filter.Ptr = (ULONGLONG)pids;
		filter.Size = sizeof(pids);
		filter.Type = EVENT_FILTER_TYPE_PID;
		ENABLE_TRACE_PARAMETERS params{};
		params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
		params.EnableFilterDesc = &filter;
		params.FilterDescCount = 1;
		error = ::EnableTraceEx2(session, &RundownProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
			LoaderRundownKeyword | StartRundownKeyword, 0, 0, &params);
		if (error == ERROR_SUCCESS) {
			// the buffers flushed often, rather than every second (FlushTimer), as the rundown takes milliseconds
			HANDLE handles[] = { hDone.get(), hCancel };
			auto start = ::GetTickCount64();
			for (;;) {
				auto elapsed = ::GetTickCount64() - start;
				if (elapsed >= timeoutMs)
					break;
				auto wait = ::WaitForMultipleObjects(hCancel ? 2 : 1, handles, FALSE, (DWORD)std::min<uint64_t>(timeoutMs - elapsed, 250));
				if (wait != WAIT_TIMEOUT)
					break;
				auto flush = Etw::MakeProperties();
				::ControlTrace(session, nullptr, &flush.Properties, EVENT_TRACE_CONTROL_FLUSH);
			}
		}
	}

	// stopping the session delivers what's still in its buffers, then ProcessTrace returns
	auto stop = Etw::MakeProperties();
	::ControlTrace(session, nullptr, &stop.Properties, EVENT_TRACE_CONTROL_STOP);
	if (hThread && ::WaitForSingleObject(hThread.get(), 5000) == WAIT_TIMEOUT) {
		::CloseTrace(trace);
		::WaitForSingleObject(hThread.get(), INFINITE);
		trace = INVALID_PROCESSTRACE_HANDLE;
	}
	if (trace != INVALID_PROCESSTRACE_HANDLE)
		::CloseTrace(trace);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return std::nullopt;
	}
	return std::move(context.Details);
}
