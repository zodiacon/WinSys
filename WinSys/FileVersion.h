#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace WinSys {
	// strings from an executable's version resource, in its first listed language (else English (US), Unicode)
	struct FileVersionInfo {
		std::wstring Description, Company, Version;
	};

	// a version resource in full: the fixed part and the strings of its first language
	struct FileVersionDetails {
		uint64_t FileVersion{ 0 }, ProductVersion{ 0 };	// VS_FIXEDFILEINFO's, four 16-bit parts from the high one
		uint32_t FileFlags{ 0 }, FileOS{ 0 }, FileType{ 0 }, FileSubtype{ 0 };
		uint16_t Language{ 0 }, CodePage{ 0 };				// the strings' (the first translation listed)
		std::vector<std::pair<std::wstring, std::wstring>> Strings;	// the standard names that have a value, in a fixed order
	};

	struct FileVersion final {
		// empty strings if the file has no version resource
		[[nodiscard]] static FileVersionInfo Read(std::wstring const& path);
		// nothing (the last error set) if the file has no version resource
		[[nodiscard]] static std::optional<FileVersionDetails> ReadDetails(std::wstring const& path);
		// "10.0.26100.1" from a FileVersionDetails version
		[[nodiscard]] static std::wstring VersionText(uint64_t version);
	};
}
