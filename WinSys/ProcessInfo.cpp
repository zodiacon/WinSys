#include "pch.h"
#include "ProcessInfo.h"

using namespace WinSys;

const std::vector<std::shared_ptr<ThreadInfo>>& ProcessInfo::GetThreads() const {
	return m_threads;
}

const std::wstring& ProcessInfo::GetUserName() const {
	if (!m_userName.empty())
		return m_userName;

	if (UserSid) {
		WCHAR name[64], domain[64];
		DWORD lname = _countof(name), ldomain = _countof(domain);
		SID_NAME_USE use;
		if (::LookupAccountSid(nullptr, (PSID)UserSid, name, &lname, domain, &ldomain, &use))
			m_userName = domain + std::wstring(L"\\") + name;
	}
	return m_userName;
}

void ProcessInfo::AddThread(std::shared_ptr<ThreadInfo> thread) {
	m_threads.push_back(thread);
}

void ProcessInfo::ClearThreads() {
	m_threads.clear();
	m_threads.reserve(16);
}
