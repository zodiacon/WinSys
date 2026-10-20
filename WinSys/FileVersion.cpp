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
