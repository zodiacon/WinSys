#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// The page files: those in use, with their sizes (SystemPageFileInformationEx, else SystemPageFileInformation without
// the minimum and maximum), and how they're configured (the Memory Management key's PagingFiles and the values beside
// it, which the System Properties dialog writes; a change applies at the next boot). No elevation needed.
//
namespace WinSys {
	// sizes in bytes
	struct PageFileInfo {
		std::wstring Name;	// a DOS path ("C:\pagefile.sys") where it can be, else the system's name
		uint64_t Size{ 0 }, InUse{ 0 }, Peak{ 0 };
		uint64_t Minimum{ 0 }, Maximum{ 0 };	// 0 when not known
	};

	// one of PagingFiles' lines: "<path> [<initial MB> <maximum MB>]"
	struct PageFileSetting {
		std::wstring Path;
		bool SystemManaged{ true };	// no sizes, or both 0
		uint32_t InitialMB{ 0 }, MaximumMB{ 0 };
	};

	struct PageFileConfiguration {
		// "?:\pagefile.sys" alone: Windows manages the size of a page file it places itself
		bool Automatic{ false };
		std::vector<PageFileSetting> Files;	// none: no page file
		std::vector<std::wstring> Existing;	// ExistingPageFiles, the ones created at the last boot
		bool ClearAtShutdown{ false };
		bool DisablePagingExecutive{ false };	// the kernel and drivers stay in physical memory
	};

	struct PageFiles final {
		// empty if there's no page file (or the query failed: the system's query doesn't tell them apart)
		[[nodiscard]] static std::vector<PageFileInfo> Enum();
		// nothing (with the last error set) if the key can't be read
		[[nodiscard]] static std::optional<PageFileConfiguration> GetConfiguration();
	};
}
