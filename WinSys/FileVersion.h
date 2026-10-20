#pragma once

#include <string>

namespace WinSys {
	// strings from an executable's version resource, in its first listed language (else English (US), Unicode)
	struct FileVersionInfo {
		std::wstring Description, Company, Version;
	};

	struct FileVersion final {
		// empty strings if the file has no version resource
		[[nodiscard]] static FileVersionInfo Read(std::wstring const& path);
	};
}
