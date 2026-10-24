#pragma once

#include <string>

//
// Extracting a zip file with the system's tar.exe (bsdtar, in System32 since Windows 10 1803), which reads zip files:
// no shell (Compressed Folders shows progress windows) and no library of our own.
//
namespace WinSys {
	struct ZipArchive final {
		// into folder, which must exist; waits up to timeoutMs. False with the last error set (ERROR_BAD_FORMAT when
		// tar failed, ERROR_TIMEOUT)
		static bool Extract(std::wstring const& zip, std::wstring const& folder, uint32_t timeoutMs = 120000);
	};
}
