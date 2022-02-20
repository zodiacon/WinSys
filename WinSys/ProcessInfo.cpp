#include "pch.h"
#include "ProcessInfo.h"

#ifdef WINSYS_NAMESPACE
using namespace WinSys;
#endif

const std::vector<std::shared_ptr<ThreadInfo>>& ProcessInfo::GetThreads() const {
	return _threads;
}

const std::wstring& ProcessInfo::GetUserName() const {
	if (!_userName.empty())
		return _userName;

	if (UserSid) {
		WCHAR name[64], domain[64];
		DWORD lname = _countof(name), ldomain = _countof(domain);
		SID_NAME_USE use;
		if (::LookupAccountSid(nullptr, (PSID)UserSid, name, &lname, domain, &ldomain, &use))
			_userName = domain + std::wstring(L"\\") + name;
	}
	return _userName;
}

void ProcessInfo::AddThread(std::shared_ptr<ThreadInfo> thread) {
	_threads.push_back(thread);
}

void ProcessInfo::ClearThreads() {
	_threads.clear();
	_threads.reserve(16);
}
