#include "pch.h"
#include "Service.h"
#include "Token.h"

using namespace WinSys;

Service::Service(wil::unique_schandle handle) noexcept : m_handle(std::move(handle)) {}

bool Service::Start() {
	return Start(std::vector<const wchar_t*>());
}

bool Service::Start(const std::vector<const wchar_t*>& args) {
	return ::StartService(m_handle.get(), static_cast<DWORD>(args.size()), const_cast<PCWSTR*>(args.data())) ? true : false;
}

bool Service::Stop(SERVICE_STATUS* pStatus) {
	SERVICE_STATUS status;
	if (pStatus == nullptr)
		pStatus = &status;
	return ::ControlService(m_handle.get(), SERVICE_CONTROL_STOP, pStatus) ? true : false;
}

ServiceStatusProcess Service::GetStatus() const {
	ServiceStatusProcess status{};
	DWORD len;
	::QueryServiceStatusEx(m_handle.get(), SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &len);
	return status;
}

std::vector<ServiceTrigger> Service::GetTriggers() const {
	std::vector<ServiceTrigger> triggers;
	DWORD needed;
	::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_TRIGGER_INFO, nullptr, 0, &needed);
	if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return triggers;

	auto buffer = std::make_unique<BYTE[]>(needed);
	if (!::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_TRIGGER_INFO, buffer.get(), needed, &needed))
		return triggers;

	auto info = reinterpret_cast<SERVICE_TRIGGER_INFO*>(buffer.get());
	triggers.reserve(info->cTriggers);
	for (DWORD i = 0; i < info->cTriggers; i++) {
		const auto& tinfo = info->pTriggers[i];
		ServiceTrigger trigger;
		trigger.Type = static_cast<ServiceTriggerType>(tinfo.dwTriggerType);
		trigger.TriggerSubtype = tinfo.pTriggerSubtype;
		trigger.Action = static_cast<ServiceTriggerAction>(tinfo.dwAction);

		triggers.push_back(trigger);
	}

	return triggers;
}

std::vector<ServiceTriggerDetails> Service::GetTriggerDetails() const {
	std::vector<ServiceTriggerDetails> triggers;
	DWORD needed = 0;
	::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_TRIGGER_INFO, nullptr, 0, &needed);
	if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return triggers;
	auto buffer = std::make_unique<BYTE[]>(needed);
	if (!::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_TRIGGER_INFO, buffer.get(), needed, &needed))
		return triggers;

	auto info = reinterpret_cast<SERVICE_TRIGGER_INFO*>(buffer.get());
	triggers.reserve(info->cTriggers);
	for (DWORD i = 0; i < info->cTriggers; i++) {
		auto& t = info->pTriggers[i];
		ServiceTriggerDetails trigger{ (ServiceTriggerType)t.dwTriggerType, (ServiceTriggerAction)t.dwAction, t.pTriggerSubtype ? *t.pTriggerSubtype : GUID{} };
		for (DWORD j = 0; j < t.cDataItems; j++) {
			auto& item = t.pDataItems[j];
			trigger.Data.push_back({ (ServiceTriggerDataType)item.dwDataType, std::vector<BYTE>(item.pData, item.pData + item.cbData) });
		}
		triggers.push_back(std::move(trigger));
	}
	return triggers;
}

std::wstring Service::GetEventProviderName(GUID const& provider) {
	WCHAR guid[64];
	if (!::StringFromGUID2(provider, guid, _countof(guid)))
		return L"";
	std::wstring key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\";
	key += guid;
	WCHAR name[256];
	DWORD size = sizeof(name);
	if (::RegGetValue(HKEY_LOCAL_MACHINE, key.c_str(), nullptr, RRF_RT_REG_SZ, nullptr, name, &size) != ERROR_SUCCESS)
		return L"";
	return name;
}

std::vector<std::wstring> Service::GetRequiredPrivileges() const {
	std::vector<std::wstring> privileges;
	DWORD needed;
	::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, nullptr, 0, &needed);
	if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return privileges;

	auto buffer = std::make_unique<BYTE[]>(needed);
	if (!::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, buffer.get(), needed, &needed))
		return privileges;

	auto info = reinterpret_cast<SERVICE_REQUIRED_PRIVILEGES_INFO*>(buffer.get());
	auto p = info->pmszRequiredPrivileges;
	while (p && *p) {
		privileges.emplace_back(p);
		p += ::wcslen(p) + 1;
	}
	return privileges;
}

ServiceSidType WinSys::Service::GetSidType() const {
	ServiceSidType type;
	DWORD len;
	if (::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_SERVICE_SID_INFO, (BYTE*)&type, sizeof(type), &len))
		return type;
	return ServiceSidType::Unknown;
}

std::vector<ServiceDependent> Service::GetDependents(ServiceEnumState state) const {
	std::vector<ServiceDependent> dependents;
	DWORD needed = 0, count = 0;
	if (::EnumDependentServices(m_handle.get(), (DWORD)state, nullptr, 0, &needed, &count)) {
		// none
		::SetLastError(ERROR_SUCCESS);
		return dependents;
	}
	if (::GetLastError() != ERROR_MORE_DATA)
		return dependents;
	// dependents may come between the calls
	for (int i = 0; i < 4; i++) {
		needed += 1 << 10;
		auto buffer = std::make_unique<BYTE[]>(needed);
		if (::EnumDependentServices(m_handle.get(), (DWORD)state, (ENUM_SERVICE_STATUS*)buffer.get(), needed, &needed, &count)) {
			auto services = (ENUM_SERVICE_STATUS*)buffer.get();
			dependents.reserve(count);
			for (DWORD j = 0; j < count; j++)
				dependents.push_back({ services[j].lpServiceName, services[j].lpDisplayName, (ServiceState)services[j].ServiceStatus.dwCurrentState });
			return dependents;
		}
		if (::GetLastError() != ERROR_MORE_DATA)
			break;
	}
	return dependents;
}

std::vector<BYTE> Service::GetSecurity(SECURITY_INFORMATION info) const {
	std::vector<BYTE> sd;
	DWORD needed = 0;
	if (!::QueryServiceObjectSecurity(m_handle.get(), info, nullptr, 0, &needed) && ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return sd;
	sd.resize(needed);
	if (!::QueryServiceObjectSecurity(m_handle.get(), info, sd.data(), needed, &needed))
		sd.clear();
	return sd;
}

bool Service::SetSecurity(SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd) {
	return ::SetServiceObjectSecurity(m_handle.get(), info, sd) ? true : false;
}

GENERIC_MAPPING const& Service::GetGenericMapping() {
	// as the SCM documents it
	static GENERIC_MAPPING const mapping{
		STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS,
		STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
		STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL,
		SERVICE_ALL_ACCESS,
	};
	return mapping;
}

std::unique_ptr<WinSys::Service> Service::Open(const std::wstring & name, ServiceAccessMask access) noexcept {
	auto hService = ServiceManager::OpenServiceHandle(name, access);
	if (!hService)
		return nullptr;

	return std::make_unique<WinSys::Service>(std::move(hService));
}

bool Service::Refresh(ServiceInfo& info) {
	DWORD bytes;
	return ::QueryServiceStatusEx(m_handle.get(), SC_STATUS_PROCESS_INFO, (BYTE*)&info._status, sizeof(SERVICE_STATUS_PROCESS), &bytes);
}

bool Service::Pause() {
	SERVICE_STATUS status;
	return ::ControlService(m_handle.get(), SERVICE_CONTROL_PAUSE, &status) ? true : false;
}

bool Service::Continue() {
	SERVICE_STATUS status;
	return ::ControlService(m_handle.get(), SERVICE_CONTROL_CONTINUE, &status) ? true : false;
}

bool Service::ChangeConfig(ServiceConfigChange const& change) {
	auto text = [](std::optional<std::wstring> const& value) { return value ? value->c_str() : nullptr; };
	return ::ChangeServiceConfig(m_handle.get(), SERVICE_NO_CHANGE,
		change.StartType ? (DWORD)*change.StartType : SERVICE_NO_CHANGE,
		change.ErrorControl ? (DWORD)*change.ErrorControl : SERVICE_NO_CHANGE,
		text(change.BinaryPath), nullptr, nullptr, nullptr, text(change.Account), text(change.Password),
		text(change.DisplayName)) ? true : false;
}

bool Service::SetDescription(std::wstring const& description) {
	SERVICE_DESCRIPTION info{ const_cast<PWSTR>(description.c_str()) };
	return ::ChangeServiceConfig2(m_handle.get(), SERVICE_CONFIG_DESCRIPTION, &info) ? true : false;
}

bool Service::SetDelayedAutoStart(bool delayed) {
	SERVICE_DELAYED_AUTO_START_INFO info{ delayed };
	return ::ChangeServiceConfig2(m_handle.get(), SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info) ? true : false;
}

std::optional<ServiceFailureActions> Service::GetFailureActions() const {
	DWORD needed = 0;
	::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_FAILURE_ACTIONS, nullptr, 0, &needed);
	if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return std::nullopt;
	auto buffer = std::make_unique<BYTE[]>(needed);
	if (!::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_FAILURE_ACTIONS, buffer.get(), needed, &needed))
		return std::nullopt;

	auto info = reinterpret_cast<SERVICE_FAILURE_ACTIONS const*>(buffer.get());
	ServiceFailureActions actions;
	actions.ResetPeriod = info->dwResetPeriod;
	if (info->lpRebootMsg)
		actions.RebootMessage = info->lpRebootMsg;
	if (info->lpCommand)
		actions.Command = info->lpCommand;
	for (DWORD i = 0; i < info->cActions; i++)
		actions.Actions.push_back({ (ServiceFailureActionType)info->lpsaActions[i].Type, info->lpsaActions[i].Delay });

	SERVICE_FAILURE_ACTIONS_FLAG flag{};
	if (::QueryServiceConfig2(m_handle.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, (BYTE*)&flag, sizeof(flag), &needed))
		actions.OnNonCrashFailures = flag.fFailureActionsOnNonCrashFailures;
	return actions;
}

bool Service::SetFailureActions(ServiceFailureActions const& actions) {
	std::vector<SC_ACTION> list;
	bool reboot = false;
	for (auto& a : actions.Actions) {
		list.push_back({ (SC_ACTION_TYPE)a.Type, a.Delay });
		reboot |= a.Type == ServiceFailureActionType::Reboot;
	}
	// with no actions, a non-null array (of none) deletes them; a null one would leave them
	SC_ACTION none{};
	SERVICE_FAILURE_ACTIONS info{ actions.ResetPeriod, const_cast<PWSTR>(actions.RebootMessage.c_str()),
		const_cast<PWSTR>(actions.Command.c_str()), (DWORD)list.size(), list.empty() ? &none : list.data() };

	// a reboot action is accepted only with SeShutdownPrivilege enabled
	std::unique_ptr<Token> token;
	if (reboot && (token = Token::Open(::GetCurrentProcessId(), TokenAccessMask::Query | TokenAccessMask::AdjustPrivileges)))
		token->EnablePrivilege(SE_SHUTDOWN_NAME, true);
	auto ok = ::ChangeServiceConfig2(m_handle.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &info);
	auto error = ::GetLastError();
	if (token)
		token->EnablePrivilege(SE_SHUTDOWN_NAME, false);
	if (!ok) {
		::SetLastError(error);
		return false;
	}
	SERVICE_FAILURE_ACTIONS_FLAG flag{ actions.OnNonCrashFailures };
	return ::ChangeServiceConfig2(m_handle.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag) ? true : false;
}
