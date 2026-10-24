#include "pch.h"
#include "Http.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp")

using namespace WinSys;

namespace {
	struct InternetCloser {
		void operator()(HINTERNET h) const noexcept {
			::WinHttpCloseHandle(h);
		}
	};
	using unique_hinternet = std::unique_ptr<void, InternetCloser>;
}

std::optional<HttpResponse> Http::Get(std::wstring const& host, std::wstring const& path, std::wstring const& userAgent,
	std::wstring const& headers, uint32_t timeoutMs) {
	unique_hinternet session(::WinHttpOpen(userAgent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0));
	if (!session)
		return std::nullopt;
	::WinHttpSetTimeouts(session.get(), timeoutMs, timeoutMs, timeoutMs, timeoutMs);
	unique_hinternet connection(::WinHttpConnect(session.get(), host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0));
	unique_hinternet request(connection ? ::WinHttpOpenRequest(connection.get(), L"GET", path.c_str(), nullptr,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr);
	if (!request)
		return std::nullopt;
	if (!::WinHttpSendRequest(request.get(), headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
		headers.empty() ? 0 : (DWORD)headers.size(), WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
		|| !::WinHttpReceiveResponse(request.get(), nullptr))
		return std::nullopt;

	HttpResponse response;
	DWORD status = 0, size = sizeof(status);
	::WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
		&status, &size, WINHTTP_NO_HEADER_INDEX);
	response.Status = status;
	for (;;) {
		DWORD available = 0;
		if (!::WinHttpQueryDataAvailable(request.get(), &available) || available == 0)
			break;
		auto offset = response.Body.size();
		response.Body.resize(offset + available);
		DWORD read = 0;
		if (!::WinHttpReadData(request.get(), response.Body.data() + offset, available, &read))
			return std::nullopt;
		response.Body.resize(offset + read);
	}
	return response;
}

bool Http::Download(std::wstring const& url, std::wstring const& path, std::wstring const& userAgent, DownloadProgress* progress,
	uint32_t* status, uint32_t timeoutMs) {
	URL_COMPONENTS parts{ sizeof(parts) };
	parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = (DWORD)-1;
	if (!::WinHttpCrackUrl(url.c_str(), 0, 0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS) {
		::SetLastError(ERROR_WINHTTP_UNRECOGNIZED_SCHEME);
		return false;
	}
	std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
	std::wstring target(parts.lpszUrlPath, parts.dwUrlPathLength + parts.dwExtraInfoLength);

	unique_hinternet session(::WinHttpOpen(userAgent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0));
	if (!session)
		return false;
	::WinHttpSetTimeouts(session.get(), timeoutMs, timeoutMs, timeoutMs, timeoutMs);
	unique_hinternet connection(::WinHttpConnect(session.get(), host.c_str(), parts.nPort, 0));
	unique_hinternet request(connection ? ::WinHttpOpenRequest(connection.get(), L"GET", target.c_str(), nullptr,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr);
	if (!request)
		return false;
	if (!::WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
		|| !::WinHttpReceiveResponse(request.get(), nullptr))
		return false;
	DWORD code = 0, size = sizeof(code);
	::WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
		&code, &size, WINHTTP_NO_HEADER_INDEX);
	if (status)
		*status = code;
	if (code != 200) {
		::SetLastError(ERROR_WINHTTP_INVALID_SERVER_RESPONSE);
		return false;
	}
	uint64_t total = 0;
	WCHAR length[32];
	size = sizeof(length);
	if (::WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, length, &size, WINHTTP_NO_HEADER_INDEX))
		total = ::_wcstoui64(length, nullptr, 10);

	HANDLE file = ::CreateFile(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	bool ok = true;
	DWORD error = 0;
	uint64_t received = 0;
	std::vector<uint8_t> buffer(1 << 16);
	for (;;) {
		DWORD read = 0, written;
		if (!::WinHttpReadData(request.get(), buffer.data(), (DWORD)buffer.size(), &read)) {
			ok = false;
			error = ::GetLastError();
			break;
		}
		if (read == 0)
			break;
		if (!::WriteFile(file, buffer.data(), read, &written, nullptr)) {
			ok = false;
			error = ::GetLastError();
			break;
		}
		received += read;
		if (progress && !progress->OnProgress(received, total)) {
			ok = false;
			error = ERROR_CANCELLED;
			break;
		}
	}
	if (ok && total && received != total) {
		ok = false;
		error = ERROR_HANDLE_EOF;
	}
	::CloseHandle(file);
	if (!ok) {
		::DeleteFile(path.c_str());
		::SetLastError(error);
	}
	return ok;
}
