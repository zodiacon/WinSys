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

void ProcessInfo::Detach() {
	if (m_Detached || !NativeInfo)
		return;
	auto entry = reinterpret_cast<BYTE const*>(NativeInfo);
	// the entry runs to the next one; the last has no next, so its size is worked out from what's in it
	size_t size = NativeInfo->NextEntryOffset;
	if (size == 0) {
		size = FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads) + sizeof(SYSTEM_EXTENDED_THREAD_INFORMATION) * NativeInfo->NumberOfThreads;
		if (ExtendedInfo) {
			auto ext = reinterpret_cast<BYTE const*>(ExtendedInfo);
			size_t end = sizeof(SYSTEM_PROCESS_INFORMATION_EXTENSION);
			if (ExtendedInfo->UserSidOffset)
				end = (std::max)(end, ExtendedInfo->UserSidOffset + (size_t)::GetLengthSid((PSID)(ext + ExtendedInfo->UserSidOffset)));
			if (ExtendedInfo->PackageFullNameOffset)
				end = (std::max)(end, ExtendedInfo->PackageFullNameOffset
					+ (::wcslen((PCWSTR)(ext + ExtendedInfo->PackageFullNameOffset)) + 1) * sizeof(WCHAR));
			size = (std::max)(size, size_t(ext - entry) + end);
		}
		// the image name is stored in the entry too, after the rest
		auto name = reinterpret_cast<BYTE const*>(NativeInfo->ImageName.Buffer);
		if (name > entry)
			size = (std::max)(size, size_t(name - entry) + NativeInfo->ImageName.MaximumLength);
	}
	m_Detached = std::make_unique<BYTE[]>(size);
	memcpy(m_Detached.get(), entry, size);
	auto moved = [&](void const* p) { return p ? m_Detached.get() + (reinterpret_cast<BYTE const*>(p) - entry) : nullptr; };
	ExtendedInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_EXTENSION const*>(moved(ExtendedInfo));
	m_PackageFullName = reinterpret_cast<PCWSTR>(moved(m_PackageFullName));
	auto info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(m_Detached.get());
	if (auto name = reinterpret_cast<BYTE const*>(info->ImageName.Buffer); name >= entry && name < entry + size)
		info->ImageName.Buffer = reinterpret_cast<PWSTR>(moved(name));
	else
		info->ImageName = {};
	NativeInfo = info;
	ClearThreads();
}

void ProcessInfo::ClearThreads() {
	m_threads.clear();
	m_threads.reserve(16);
}
