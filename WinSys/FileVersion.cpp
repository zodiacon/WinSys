#include "pch.h"
#include "FileVersion.h"

#pragma comment(lib, "version")

using namespace WinSys;

FileVersionInfo FileVersion::Read(std::wstring const& path) {
	FileVersionInfo info;
	DWORD handle;
	auto size = ::GetFileVersionInfoSize(path.c_str(), &handle);
	if (size == 0)
		return info;
	auto buffer = std::make_unique<BYTE[]>(size);
	if (!::GetFileVersionInfo(path.c_str(), 0, size, buffer.get()))
		return info;

	// the first language listed; English (US), Unicode if there's no list
	struct Translation {
		WORD Language, CodePage;
	} *translation;
	UINT len;
	WCHAR prefix[64] = L"\\StringFileInfo\\040904B0\\";
	if (::VerQueryValue(buffer.get(), L"\\VarFileInfo\\Translation", (void**)&translation, &len) && len >= sizeof(Translation))
		::StringCchPrintf(prefix, _countof(prefix), L"\\StringFileInfo\\%04X%04X\\", translation->Language, translation->CodePage);
	auto query = [&](PCWSTR name) -> std::wstring {
		PCWSTR text;
		if (!::VerQueryValue(buffer.get(), (std::wstring(prefix) + name).c_str(), (void**)&text, &len) || len == 0)
			return L"";
		return text;
	};
	info.Description = query(L"FileDescription");
	info.Company = query(L"CompanyName");
	info.Version = query(L"FileVersion");
	return info;
}

std::optional<FileVersionDetails> FileVersion::ReadDetails(std::wstring const& path) {
	DWORD handle;
	auto size = ::GetFileVersionInfoSize(path.c_str(), &handle);
	if (size == 0)
		return std::nullopt;
	auto buffer = std::make_unique<BYTE[]>(size);
	if (!::GetFileVersionInfo(path.c_str(), 0, size, buffer.get()))
		return std::nullopt;
	FileVersionDetails details;
	VS_FIXEDFILEINFO* fixed;
	UINT len;
	if (::VerQueryValue(buffer.get(), L"\\", (void**)&fixed, &len) && len >= sizeof(VS_FIXEDFILEINFO) && fixed->dwSignature == VS_FFI_SIGNATURE) {
		details.FileVersion = ((uint64_t)fixed->dwFileVersionMS << 32) | fixed->dwFileVersionLS;
		details.ProductVersion = ((uint64_t)fixed->dwProductVersionMS << 32) | fixed->dwProductVersionLS;
		details.FileFlags = fixed->dwFileFlags & fixed->dwFileFlagsMask;
		details.FileOS = fixed->dwFileOS;
		details.FileType = fixed->dwFileType;
		details.FileSubtype = fixed->dwFileSubtype;
	}
	struct Translation {
		WORD Language, CodePage;
	} *translation;
	details.Language = 0x0409;
	details.CodePage = 1200;
	if (::VerQueryValue(buffer.get(), L"\\VarFileInfo\\Translation", (void**)&translation, &len) && len >= sizeof(Translation)) {
		details.Language = translation->Language;
		details.CodePage = translation->CodePage;
	}
	WCHAR prefix[64];
	::StringCchPrintf(prefix, _countof(prefix), L"\\StringFileInfo\\%04X%04X\\", details.Language, details.CodePage);
	for (auto name : { L"FileDescription", L"FileVersion", L"ProductName", L"ProductVersion", L"CompanyName", L"LegalCopyright",
		L"LegalTrademarks", L"OriginalFilename", L"InternalName", L"Comments", L"PrivateBuild", L"SpecialBuild" }) {
		PCWSTR text;
		if (::VerQueryValue(buffer.get(), (std::wstring(prefix) + name).c_str(), (void**)&text, &len) && len > 0 && *text)
			details.Strings.push_back({ name, text });
	}
	return details;
}

std::wstring FileVersion::VersionText(uint64_t version) {
	return std::to_wstring((version >> 48) & 0xFFFF) + L"." + std::to_wstring((version >> 32) & 0xFFFF) + L"."
		+ std::to_wstring((version >> 16) & 0xFFFF) + L"." + std::to_wstring(version & 0xFFFF);
}
