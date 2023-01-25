#include "pch.h"
#include "ProcessInfo.h"

using namespace WinSys;

const std::vector<std::shared_ptr<ThreadInfo>>& ProcessInfo::GetThreads() const {
	return m_threads;
}

const std::wstring& ProcessInfo::GetUserName() const {
	if (!m_UserName.empty())
		return m_UserName;

	if (ExtendedInfo && ExtendedInfo->UserSidOffset) {
		auto sid = (PSID)((PBYTE)ExtendedInfo + ExtendedInfo->UserSidOffset);
		WCHAR name[64], domain[64];
		DWORD lname = _countof(name), ldomain = _countof(domain);
		SID_NAME_USE use;
		if (::LookupAccountSid(nullptr, sid, name, &lname, domain, &ldomain, &use))
			m_UserName = domain + std::wstring(L"\\") + name;
	}
	return m_UserName;
}

void ProcessInfo::AddThread(std::shared_ptr<ThreadInfo> thread) {
	m_threads.push_back(std::move(thread));
}

void ProcessInfo::ClearThreads() {
	m_threads.clear();
	m_threads.reserve(16);
}
