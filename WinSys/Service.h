#pragma once

#include <memory>
#include <string>
#include "ServiceManager.h"

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

	private:
		wil::unique_schandle m_handle;
	};

}
