#include "pch.h"
#include "DotNet.h"
#include <wil/resource.h>

using namespace WinSys;

bool DotNetInfo::HasFrameworkRuntime(uint32_t pid, uint32_t sessionId) {
	for (auto name : { L"Cor_Private_IPCBlock_v4_", L"Cor_Private_IPCBlock_" }) {
		auto path = (sessionId == 0 ? std::wstring(L"\\BaseNamedObjects\\")
			: L"\\Sessions\\" + std::to_wstring(sessionId) + L"\\BaseNamedObjects\\") + name + std::to_wstring(pid);
		UNICODE_STRING uname;
		::RtlInitUnicodeString(&uname, path.c_str());
		OBJECT_ATTRIBUTES attr;
		InitializeObjectAttributes(&attr, &uname, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		HANDLE hSection;
		auto status = ::NtOpenSection(&hSection, SECTION_QUERY, &attr);
		if (NT_SUCCESS(status))
			::NtClose(hSection);
		// another user's section exists even if it can't be opened
		if (NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED)
			return true;
	}
	return false;
}

std::unordered_set<uint32_t> DotNetInfo::GetCoreRuntimeProcesses() {
	std::unordered_set<uint32_t> pids;
	const std::wstring_view prefix = L"dotnet-diagnostic-";
	WIN32_FIND_DATA fd;
	wil::unique_hfind hFind(::FindFirstFile(L"\\\\.\\pipe\\*", &fd));
	if (!hFind)
		return pids;
	do {
		if (std::wstring_view(fd.cFileName).starts_with(prefix))
			if (auto pid = ::wcstoul(fd.cFileName + prefix.size(), nullptr, 10))
				pids.insert(pid);
	} while (::FindNextFile(hFind.get(), &fd));
	return pids;
}
