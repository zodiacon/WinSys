#include "pch.h"
#include "VirusTotal.h"
#include <wil/resource.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <vector>

#pragma comment(lib, "winhttp")
#pragma comment(lib, "bcrypt")

using namespace WinSys;

namespace {
	constexpr PCWSTR Host = L"www.virustotal.com";
	constexpr uint64_t DirectUploadLimit = 32ull << 20, UploadLimit = 650ull << 20;

	using unique_hinternet = wil::unique_any<HINTERNET, decltype(&::WinHttpCloseHandle), ::WinHttpCloseHandle>;

	struct Response {
		uint32_t Status{ 0 };
		uint32_t Error{ 0 };
		std::string Body;
	};

	// one request to host (https), the key in x-apikey; extraHeaders end with CRLF
	Response Send(std::wstring const& host, std::wstring const& path, PCWSTR verb, std::wstring const& apiKey,
		std::wstring const& extraHeaders, void const* body, uint32_t bodySize) {
		Response response;
		unique_hinternet session(::WinHttpOpen(L"WinSysLive", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0));
		if (!session) {
			response.Error = ::GetLastError();
			return response;
		}
		// resolve, connect, send, receive: an upload may take minutes
		::WinHttpSetTimeouts(session.get(), 15000, 15000, 300000, 60000);
		unique_hinternet connection(::WinHttpConnect(session.get(), host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0));
		unique_hinternet request(connection ? ::WinHttpOpenRequest(connection.get(), verb, path.c_str(), nullptr,
			WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr);
		if (!request) {
			response.Error = ::GetLastError();
			return response;
		}
		std::wstring headers = L"x-apikey: " + apiKey + L"\r\naccept: application/json\r\n" + extraHeaders;
		if (!::WinHttpSendRequest(request.get(), headers.c_str(), (DWORD)headers.size(), const_cast<void*>(body), bodySize,
			bodySize, 0) || !::WinHttpReceiveResponse(request.get(), nullptr)) {
			response.Error = ::GetLastError();
			return response;
		}
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
				break;
			response.Body.resize(offset + read);
		}
		return response;
	}

	// the number after "key": in the object that follows "object": (a small JSON reader for the fields needed)
	std::optional<int64_t> FindNumber(std::string const& json, size_t from, size_t to, char const* key) {
		std::string quoted = std::string("\"") + key + "\"";
		auto pos = json.find(quoted, from);
		if (pos == std::string::npos || pos >= to)
			return std::nullopt;
		pos = json.find(':', pos + quoted.size());
		if (pos == std::string::npos)
			return std::nullopt;
		pos = json.find_first_not_of(" \t\r\n", pos + 1);
		if (pos == std::string::npos || !(isdigit((unsigned char)json[pos]) || json[pos] == '-'))
			return std::nullopt;
		return _strtoi64(json.c_str() + pos, nullptr, 10);
	}

	// the span of the object that's the value of key
	std::pair<size_t, size_t> FindObject(std::string const& json, char const* key) {
		std::string quoted = std::string("\"") + key + "\"";
		auto pos = json.find(quoted);
		if (pos == std::string::npos)
			return { std::string::npos, std::string::npos };
		auto open = json.find('{', pos);
		if (open == std::string::npos)
			return { std::string::npos, std::string::npos };
		int depth = 0;
		bool inString = false;
		for (auto i = open; i < json.size(); i++) {
			char c = json[i];
			if (inString) {
				if (c == '\\')
					i++;
				else if (c == '"')
					inString = false;
			}
			else if (c == '"')
				inString = true;
			else if (c == '{')
				depth++;
			else if (c == '}' && --depth == 0)
				return { open, i };
		}
		return { std::string::npos, std::string::npos };
	}

	// the string value of key (no escapes expected: a URL)
	std::string FindString(std::string const& json, char const* key) {
		std::string quoted = std::string("\"") + key + "\"";
		auto pos = json.find(quoted);
		if (pos == std::string::npos)
			return {};
		pos = json.find('"', json.find(':', pos + quoted.size()));
		if (pos == std::string::npos)
			return {};
		auto end = json.find('"', pos + 1);
		return end == std::string::npos ? std::string() : json.substr(pos + 1, end - pos - 1);
	}

	VirusTotalReport FromResponse(Response const& response) {
		VirusTotalReport report;
		report.HttpStatus = response.Status;
		report.Error = response.Error;
		switch (response.Status) {
			case 200: report.Status = VirusTotalStatus::Found; break;
			case 404: report.Status = VirusTotalStatus::NotFound; break;
			case 401: case 403: report.Status = VirusTotalStatus::BadKey; break;
			case 429: report.Status = VirusTotalStatus::QuotaExceeded; break;
			default: report.Status = VirusTotalStatus::Error; break;
		}
		return report;
	}

	std::wstring Widen(std::string const& text) {
		std::wstring result(text.size(), L'\0');
		int count = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), result.data(), (int)result.size());
		result.resize(count > 0 ? count : 0);
		return result;
	}

	std::string Narrow(std::wstring const& text) {
		int count = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0, nullptr, nullptr);
		std::string result(count > 0 ? count : 0, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), result.data(), count, nullptr, nullptr);
		return result;
	}
}

std::wstring VirusTotal::ReportUrl(std::wstring const& sha256) {
	return L"https://www.virustotal.com/gui/file/" + sha256;
}

VirusTotalReport VirusTotal::LookupHash(std::wstring const& apiKey, std::wstring const& sha256) {
	auto response = Send(Host, L"/api/v3/files/" + sha256, L"GET", apiKey, L"", nullptr, 0);
	auto report = FromResponse(response);
	if (report.Status != VirusTotalStatus::Found)
		return report;
	auto [from, to] = FindObject(response.Body, "last_analysis_stats");
	if (from != std::string::npos) {
		auto get = [&](char const* key) { return (uint32_t)FindNumber(response.Body, from, to, key).value_or(0); };
		report.Malicious = get("malicious");
		report.Suspicious = get("suspicious");
		report.Undetected = get("undetected");
		report.Harmless = get("harmless");
		report.Engines = report.Malicious + report.Suspicious + report.Undetected + report.Harmless + get("timeout") + get("failure");
	}
	report.LastAnalysis = FindNumber(response.Body, 0, response.Body.size(), "last_analysis_date").value_or(0);
	return report;
}

VirusTotalReport VirusTotal::UploadFile(std::wstring const& apiKey, std::wstring const& path) {
	VirusTotalReport report;
	wil::unique_hfile file(::CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
	LARGE_INTEGER size{};
	if (!file || !::GetFileSizeEx(file.get(), &size)) {
		report.Error = ::GetLastError();
		return report;
	}
	if ((uint64_t)size.QuadPart > UploadLimit) {
		report.Status = VirusTotalStatus::TooLarge;
		return report;
	}

	// multipart/form-data with the file as the "file" field
	auto slash = path.find_last_of(L"\\/");
	auto name = Narrow(slash == std::wstring::npos ? path : path.substr(slash + 1));
	std::string boundary = "----WinSysLive" + std::to_string(::GetTickCount64());
	std::string head = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name +
		"\"\r\nContent-Type: application/octet-stream\r\n\r\n";
	std::string tail = "\r\n--" + boundary + "--\r\n";
	std::vector<char> body(head.size() + (size_t)size.QuadPart + tail.size());
	memcpy(body.data(), head.data(), head.size());
	auto data = body.data() + head.size();
	for (uint64_t offset = 0; offset < (uint64_t)size.QuadPart; ) {
		DWORD chunk = (DWORD)(std::min)((uint64_t)size.QuadPart - offset, (uint64_t)(1 << 24)), read = 0;
		if (!::ReadFile(file.get(), data + offset, chunk, &read, nullptr) || read == 0) {
			report.Error = ::GetLastError();
			return report;
		}
		offset += read;
	}
	memcpy(data + size.QuadPart, tail.data(), tail.size());
	std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + Widen(boundary) + L"\r\n";

	// a large file goes to a one-time URL
	std::wstring host = Host, target = L"/api/v3/files";
	if ((uint64_t)size.QuadPart > DirectUploadLimit) {
		auto response = Send(Host, L"/api/v3/files/upload_url", L"GET", apiKey, L"", nullptr, 0);
		if (response.Status != 200)
			return FromResponse(response);
		URL_COMPONENTS parts{ sizeof(parts) };
		WCHAR hostName[256], urlPath[2048];
		parts.lpszHostName = hostName;
		parts.dwHostNameLength = _countof(hostName);
		parts.lpszUrlPath = urlPath;
		parts.dwUrlPathLength = _countof(urlPath);
		auto url = Widen(FindString(response.Body, "data"));
		if (url.empty() || !::WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) {
			report.Error = url.empty() ? ERROR_INVALID_DATA : ::GetLastError();
			return report;
		}
		host.assign(parts.lpszHostName, parts.dwHostNameLength);
		target.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
	}
	auto response = Send(host, target, L"POST", apiKey, headers, body.data(), (uint32_t)body.size());
	report = FromResponse(response);
	if (report.Status == VirusTotalStatus::Found)
		report.Status = VirusTotalStatus::Uploaded;
	return report;
}

std::optional<std::wstring> FileHash::Sha256(std::wstring const& path) {
	wil::unique_hfile file(::CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
	if (!file)
		return std::nullopt;
	BCRYPT_ALG_HANDLE alg;
	if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
		::SetLastError(ERROR_NOT_SUPPORTED);
		return std::nullopt;
	}
	BCRYPT_HASH_HANDLE hash = nullptr;
	std::optional<std::wstring> result;
	if (BCRYPT_SUCCESS(::BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
		std::vector<BYTE> buffer(1 << 20);
		bool ok = true;
		for (;;) {
			DWORD read = 0;
			if (!::ReadFile(file.get(), buffer.data(), (DWORD)buffer.size(), &read, nullptr)) {
				ok = false;
				break;
			}
			if (read == 0)
				break;
			::BCryptHashData(hash, buffer.data(), read, 0);
		}
		BYTE digest[32];
		if (ok && BCRYPT_SUCCESS(::BCryptFinishHash(hash, digest, sizeof(digest), 0))) {
			static const wchar_t hex[] = L"0123456789abcdef";
			std::wstring text;
			for (auto b : digest) {
				text += hex[b >> 4];
				text += hex[b & 15];
			}
			result = std::move(text);
		}
		::BCryptDestroyHash(hash);
	}
	::BCryptCloseAlgorithmProvider(alg, 0);
	return result;
}
