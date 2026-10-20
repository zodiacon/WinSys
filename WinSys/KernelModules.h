#pragma once

#include <vector>
#include <string>

namespace WinSys {
	//
	// The kernel's loaded modules (the kernel, the HAL, drivers), from SystemModuleInformationEx (SystemModuleInformation
	// if that fails, without the image header's values). Any caller gets the list; the bases are zero unless the caller is
	// elevated (with SeDebugPrivilege or not).
	//
	struct KernelModule {
		std::wstring Name;	// the file name ("ntoskrnl.exe")
		std::wstring Path;	// a Win32 path ("C:\Windows\system32\ntoskrnl.exe"), or the name as the kernel has it
		uint64_t Base{ 0 };	// 0 when not elevated
		uint32_t Size{ 0 };
		uint16_t LoadOrder{ 0 };	// the index in the kernel's list: the kernel is 0
		uint16_t InitOrder{ 0 };
		uint16_t LoadCount{ 0 };
		uint32_t Flags{ 0 };	// LDR_DATA_TABLE_ENTRY flags
		// from the image's header: its link time (seconds since 1970), checksum and preferred base
		uint32_t TimeDateStamp{ 0 };
		uint32_t Checksum{ 0 };
		uint64_t DefaultBase{ 0 };
	};

	struct KernelModules final {
		// in the kernel's load order; empty on failure
		[[nodiscard]] static std::vector<KernelModule> Enum();
		// a module's path as the kernel has it ("\SystemRoot\system32\ntoskrnl.exe", "\??\C:\...", "\Windows\...",
		// "\Device\HarddiskVolume3\...") as a Win32 path; unchanged if it isn't one of those
		[[nodiscard]] static std::wstring ToWin32Path(std::wstring const& path);
	};
}
