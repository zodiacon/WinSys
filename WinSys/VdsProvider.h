#pragma once

#include <wil\com.h>
#include <string>
#include <vds.h>
#include <optional>

namespace WinSys::Vds {
	enum class VdsProviderType : uint32_t {
		Unknown = 0,
		Software = 1,
		hardware = 2,
		VirtualDisk = 3,
		Max = 4
	};
	enum class VdsProviderFlags : uint32_t {
		Dynamic = 0x1,
		InternalHardwareProvider = 0x2,
		OneDiskOnlyPerPack = 0x4,
		OnePackOnlineOnly = 0x8,
		VolumeSpaceMustBeContiguous = 0x10,
		SupportDynamic = 0x80000000,
		SupportFaultTolerant = 0x40000000,
		SupportDynamic1394 = 0x20000000,
		SupportMirror = 0x20,
		SupportRaid5 = 0x40
	};
	DEFINE_ENUM_FLAG_OPERATORS(WinSys::Vds::VdsProviderFlags);

	struct VdsProviderProperties {
		GUID Id;
		std::wstring Name;
		GUID VersionId;
		std::wstring Version;
		VdsProviderType Type;
		VdsProviderFlags Flags;
		uint32_t StripSizeBits;
		uint16_t RebuildPriority;
	};

	class VdsProvider final {
	public:
		VdsProvider(IVdsProvider* provider);

		std::optional<VdsProviderProperties> GetProperties() const;

	private:
		wil::com_ptr<IVdsProvider> m_provider;
	};
}

