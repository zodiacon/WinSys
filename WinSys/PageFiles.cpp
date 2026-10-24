#include "pch.h"
#include "PageFiles.h"
#include "SystemInfo.h"
#include "Helpers.h"

using namespace WinSys;

namespace {
	const PCWSTR MemoryManagementKey = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";

	uint64_t PageSize() {
		static const uint64_t size = [] {
			SYSTEM_INFO si;
			::GetSystemInfo(&si);
			return (uint64_t)si.dwPageSize;
		}();
		return size;
	}

	// "\??\C:\pagefile.sys" (or a device's name) as a DOS path
	std::wstring DosPath(std::wstring const& name) {
		if (name.starts_with(L"\\??\\"))
			return name.substr(4);
		if (name.starts_with(L"\\Device\\"))
			return Helpers::GetDosNameFromNtName(name.c_str());
		return name;
	}

	std::vector<std::wstring> ReadMultiString(HKEY key, PCWSTR name) {
		DWORD size = 0;
		if (::RegGetValue(key, nullptr, name, RRF_RT_REG_MULTI_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS)
			return {};
		std::wstring buffer(size / sizeof(WCHAR) + 1, L'\0');
		if (::RegGetValue(key, nullptr, name, RRF_RT_REG_MULTI_SZ, nullptr, buffer.data(), &size) != ERROR_SUCCESS)
			return {};
		std::vector<std::wstring> strings;
		for (auto p = buffer.c_str(); *p; p += ::wcslen(p) + 1)
			strings.emplace_back(p);
		return strings;
	}

	bool ReadFlag(HKEY key, PCWSTR name) {
		DWORD value = 0, size = sizeof(value);
		return ::RegGetValue(key, nullptr, name, RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS && value != 0;
	}
}

std::vector<PageFileInfo> PageFiles::Enum() {
	bool ex = true;
	auto files = SystemInfo::GetPageFileInformationEx();
	if (files.empty()) {
		// before the Ex class (or no page file at all)
		ex = false;
		files = SystemInfo::GetPageFileInformation();
	}
	auto page = PageSize();
	std::vector<PageFileInfo> result;
	for (auto& f : files) {
		PageFileInfo info;
		info.Name = DosPath(f.Name);
		info.Size = (uint64_t)f.Info.TotalSize * page;
		info.InUse = (uint64_t)f.Info.TotalInUse * page;
		info.Peak = (uint64_t)f.Info.PeakUsage * page;
		if (ex) {
			info.Minimum = (uint64_t)f.Info.MinimumSize * page;
			info.Maximum = (uint64_t)f.Info.MaximumSize * page;
		}
		result.push_back(std::move(info));
	}
	return result;
}

std::optional<PageFileConfiguration> PageFiles::GetConfiguration() {
	HKEY key;
	auto error = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, MemoryManagementKey, 0, KEY_READ, &key);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return std::nullopt;
	}
	PageFileConfiguration config;
	for (auto& line : ReadMultiString(key, L"PagingFiles")) {
		// the path, then the sizes in MB, separated by spaces (a path with spaces can't be configured)
		PageFileSetting setting;
		auto space = line.find(L' ');
		setting.Path = line.substr(0, space);
		if (setting.Path.empty())
			continue;
		if (space != std::wstring::npos) {
			auto rest = line.c_str() + space;
			wchar_t* end;
			setting.InitialMB = ::wcstoul(rest, &end, 10);
			setting.MaximumMB = ::wcstoul(end, nullptr, 10);
			setting.SystemManaged = setting.InitialMB == 0 && setting.MaximumMB == 0;
		}
		if (setting.Path.starts_with(L"?:"))
			config.Automatic = true;
		config.Files.push_back(std::move(setting));
	}
	for (auto& name : ReadMultiString(key, L"ExistingPageFiles"))
		config.Existing.push_back(DosPath(name));
	config.ClearAtShutdown = ReadFlag(key, L"ClearPageFileAtShutdown");
	config.DisablePagingExecutive = ReadFlag(key, L"DisablePagingExecutive");
	::RegCloseKey(key);
	return config;
}
