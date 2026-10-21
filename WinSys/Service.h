#pragma once

#include <memory>
#include <string>
#include <optional>
#include <vector>
#include "ServiceManager.h"
#include <wil/resource.h>

namespace WinSys {
	enum class ServiceTriggerType {
		Custom = 20,
		DeviceInterfaceArrival = 1,
		DomainJoin = 3,
		FirewallPortEvent = 4,
		GroupPolicy = 5,
		IpAddressAvailability = 2,
		NetworkEndpoint = 6,
		SystemStateChanged = 7,
		Aggregate = 30
	};

	enum class ServiceSidType {
		None = SERVICE_SID_TYPE_NONE,
		Restricted = SERVICE_SID_TYPE_RESTRICTED,
		Unrestricted = SERVICE_SID_TYPE_UNRESTRICTED,
		Unknown = -1
	};

	enum class ServiceTriggerAction {
		Start = 1,
		Stop = 2
	};

	struct ServiceTrigger {
		ServiceTriggerType Type;
		ServiceTriggerAction Action;
		GUID* TriggerSubtype;
		uint32_t DataItems;
		void* pSpecificDataItems;
	};

	static_assert(sizeof(ServiceTrigger) == sizeof(SERVICE_TRIGGER));

	enum class ServiceFailureActionType {
		None = SC_ACTION_NONE,
		Restart = SC_ACTION_RESTART,
		Reboot = SC_ACTION_REBOOT,
		RunCommand = SC_ACTION_RUN_COMMAND,
	};

	struct ServiceFailureAction {
		ServiceFailureActionType Type;
		uint32_t Delay;	// ms before the action
	};

	// what the SCM does when the service fails
	struct ServiceFailureActions {
		uint32_t ResetPeriod{ 0 };	// seconds without a failure after which the count starts over; INFINITE: never
		std::wstring RebootMessage;	// broadcast before a reboot action
		std::wstring Command;		// a RunCommand action's command line
		std::vector<ServiceFailureAction> Actions;	// the first failure's, the second's...; the last one repeats
		bool OnNonCrashFailures{ false };	// also when the service stops itself with an error, not only when it crashes
	};

	// the parts of a service's configuration to change; those left empty stay as they are
	struct ServiceConfigChange {
		std::optional<ServiceStartType> StartType;
		std::optional<ServiceErrorControl> ErrorControl;
		std::optional<std::wstring> BinaryPath;
		std::optional<std::wstring> DisplayName;
		std::optional<std::wstring> Account;	// "LocalSystem", "NT AUTHORITY\LocalService", ".\user", "DOMAIN\user"...
		std::optional<std::wstring> Password;	// with Account: empty for the built-in accounts
	};

	class Service final {
	public:
		explicit Service(wil::unique_schandle) noexcept;

		static std::unique_ptr<Service> Open(const std::wstring& name, ServiceAccessMask access) noexcept;

		ServiceStatusProcess GetStatus() const;
		std::vector<ServiceTrigger> GetTriggers() const;
		std::vector<std::wstring> GetRequiredPrivileges() const;

		ServiceSidType GetSidType() const;

		bool Start();
		bool Start(const std::vector<const wchar_t*>& args);
		bool Stop(SERVICE_STATUS* status = nullptr);
		bool Pause();
		bool Continue();
		bool Delete();

		bool Refresh(ServiceInfo& info);

		// these need SERVICE_CHANGE_CONFIG (in practice, elevation); false with the last error on failure
		bool ChangeConfig(ServiceConfigChange const& change);
		bool SetDescription(std::wstring const& description);
		bool SetDelayedAutoStart(bool delayed);
		// a Restart action also needs SERVICE_START; a Reboot action needs the caller to have SeShutdownPrivilege
		// (it's enabled for the call)
		bool SetFailureActions(ServiceFailureActions const& actions);
		// SERVICE_QUERY_CONFIG; nothing on failure
		[[nodiscard]] std::optional<ServiceFailureActions> GetFailureActions() const;

	private:
		wil::unique_schandle m_handle;
	};

}
