#pragma once

#include <cstdint>
#include <optional>
#include <string>

//
// VirusTotal's public API (v3) over WinHTTP, synchronous (callers run it on threads of their own):
// - LookupHash: GET /api/v3/files/{sha256}, the file's last analysis stats, if VirusTotal knows the file. Only the
//   hash leaves the machine.
// - UploadFile: POST /api/v3/files (multipart; a file over 32 MB through an upload URL from /files/upload_url, up to
//   650 MB). The file is sent to VirusTotal, which shares it with its partners: callers ask first.
// Every request takes the API key in the x-apikey header. The free tier allows 4 requests a minute and 500 a day: the
// caller paces them (QuotaExceeded is HTTP 429). FileHash::Sha256 hashes a file (BCrypt).
//

namespace WinSys {
	enum class VirusTotalStatus {
		Found,			// the report's counts are valid
		NotFound,		// VirusTotal doesn't know the file
		Uploaded,
		BadKey,			// 401/403
		QuotaExceeded,	// 429
		TooLarge,		// over 650 MB
		Error,			// Error/HttpStatus say what
	};

	struct VirusTotalReport {
		VirusTotalStatus Status{ VirusTotalStatus::Error };
		uint32_t Malicious{ 0 }, Suspicious{ 0 }, Undetected{ 0 }, Harmless{ 0 };
		uint32_t Engines{ 0 };		// the engines that analyzed the file (not counting those that don't support its type)
		int64_t LastAnalysis{ 0 };	// Unix time; 0: never analyzed yet (an upload being analyzed)
		uint32_t HttpStatus{ 0 };
		uint32_t Error{ 0 };		// a Win32/WinHTTP error, when the request failed
	};

	struct VirusTotal final {
		[[nodiscard]] static VirusTotalReport LookupHash(std::wstring const& apiKey, std::wstring const& sha256);
		[[nodiscard]] static VirusTotalReport UploadFile(std::wstring const& apiKey, std::wstring const& path);
		// the report's page on the web site
		[[nodiscard]] static std::wstring ReportUrl(std::wstring const& sha256);
	};

	struct FileHash final {
		// lowercase hex; nothing if the file can't be read, with the last error
		[[nodiscard]] static std::optional<std::wstring> Sha256(std::wstring const& path);
	};
}
