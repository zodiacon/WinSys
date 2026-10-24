#pragma once

#include <cstdint>
#include <optional>
#include <string>

//
// A plain HTTPS GET over WinHTTP (the system's proxy settings), synchronous: callers run it off the UI thread. The
// user agent is what the caller passes; some services (GitHub's API) refuse requests without one.
//
namespace WinSys {
	struct HttpResponse {
		uint32_t Status{ 0 };	// 200...
		std::string Body;	// as received (UTF-8 for JSON)
	};

	// told of a download's progress (total 0 while unknown); false cancels it (ERROR_CANCELLED). A non-owning
	// reference, not std::function (see CLAUDE.md on exceptions)
	struct DownloadProgress {
		virtual bool OnProgress(uint64_t received, uint64_t total) = 0;
	};

	struct Http final {
		// an https:// URL (redirects followed, as GitHub's release assets need) into a file, created or replaced;
		// any status but 200 fails with ERROR_WINHTTP_INVALID_SERVER_RESPONSE, the status in *status. The file is
		// deleted on failure
		static bool Download(std::wstring const& url, std::wstring const& path, std::wstring const& userAgent,
			DownloadProgress* progress = nullptr, uint32_t* status = nullptr, uint32_t timeoutMs = 60000);

		// nothing (with the last error set) if the request couldn't be made; a response with any status otherwise.
		// headers: extra request headers, each ending with CRLF
		[[nodiscard]] static std::optional<HttpResponse> Get(std::wstring const& host, std::wstring const& path,
			std::wstring const& userAgent, std::wstring const& headers = {}, uint32_t timeoutMs = 15000);
	};
}
