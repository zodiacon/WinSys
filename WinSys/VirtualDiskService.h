#pragma once

#define INITGUID
#include <vds.h>
#include <wil\com.h>
#include <string>
#include <string_view>
#include <vector>
#include "VdsProvider.h"

namespace WinSys::Vds {
	enum class VdsServiceFlags : uint32_t {
		SupportDynamic = 1,
		SupportFaultTolerant = 2,
		SupportGpt = 4,
		SupportDynamic1394 = 8,
		ClusterServiceConfigured = 0x10,
		AutoMountOff = 0x20,
		OSUninstallValid = 0x40,
		EFI = 0x80,
		SupportMirror = 0x100,
		SupportRaid5 = 0x200,
		SupportRefs = 0x400
	};
	DEFINE_ENUM_FLAG_OPERATORS(WinSys::Vds::VdsServiceFlags);

	struct VdsServiceProperties {
		std::wstring Version;
		VdsServiceFlags Flags;
	};

	enum class VdsProviderMask {
		Software = 0x1,
		Hardware = 0x2,
		VirtualDisk = 0x4,
		All = Software | Hardware | VirtualDisk,
	};
	DEFINE_ENUM_FLAG_OPERATORS(WinSys::Vds::VdsProviderMask);

	class VirtualDiskService final {
	public:
		bool Load(std::wstring_view computerName = L"");
		explicit operator IVdsService* () {
			return m_svc.get();
		}

		bool IsServiceReady() const;
		bool WaitForServiceReady();
		bool Reenumerate();
		bool Refresh();
		VdsServiceProperties GetProperties() const;
		std::vector<VdsProvider> QueryProviders(VdsProviderMask mask);

	private:
		wil::com_ptr<IVdsService> m_svc;
	};
}

