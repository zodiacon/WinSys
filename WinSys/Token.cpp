#include "pch.h"
#include "Token.h"
#include <assert.h>

using namespace WinSys;

Token::Token(HANDLE hToken) noexcept : m_Handle(hToken) {
}

bool Token::OpenProcessToken(DWORD pid, TokenAccessMask access) noexcept {
	if (wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)); hProcess) {
		::OpenProcessToken(hProcess.get(), static_cast<DWORD>(access), m_Handle.addressof());
	}
	return m_Handle.is_valid();
}

Token::Token(HANDLE hProcess, TokenAccessMask access) noexcept {
	::OpenProcessToken(hProcess, static_cast<DWORD>(access), m_Handle.addressof());
}

std::unique_ptr<Token> Token::Open(DWORD pid, TokenAccessMask access) {
	HANDLE hToken;
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
	if (hProcess) {
		if (::OpenProcessToken(hProcess.get(), static_cast<DWORD>(access), &hToken))
			return std::make_unique<Token>(hToken);
	}
	return nullptr;
}

std::pair<std::wstring, Sid> Token::GetUserNameAndSid() const {
	assert(m_Handle);
	BYTE buffer[256];
	DWORD len;
	if (::GetTokenInformation(m_Handle.get(), TokenUser, buffer, sizeof(buffer), &len)) {
		auto data = (TOKEN_USER*)buffer;
		Sid sid(data->User.Sid);
		WCHAR name[64], domain[64];
		DWORD lname = _countof(name), ldomain = _countof(domain);
		SID_NAME_USE use;
		std::wstring username;
		if (::LookupAccountSid(nullptr, sid, name, &lname, domain, &ldomain, &use))
			username = std::wstring(domain) + L"\\" + name;
		return { username, sid };
	}
	return { L"", Sid() };
}

std::wstring WinSys::Token::GetUserName() const {
	return GetUserNameAndSid().first;
}

bool Token::IsValid() const noexcept {
	return m_Handle != nullptr;
}

WinSys::Token::operator bool() const noexcept {
	return IsValid();
}

bool Token::IsElevated() const noexcept {
	ULONG elevated = 0;
	DWORD len;
	::GetTokenInformation(m_Handle.get(), TokenElevation, &elevated, sizeof(elevated), &len);
	return elevated ? true : false;
}

VirtualizationState Token::GetVirtualizationState() const noexcept {
	ULONG virt = 0;
	DWORD len;
	if (!::GetTokenInformation(m_Handle.get(), TokenVirtualizationAllowed, &virt, sizeof(virt), &len))
		return VirtualizationState::Unknown;

	if (!virt)
		return VirtualizationState::NotAllowed;

	if (::GetTokenInformation(m_Handle.get(), TokenVirtualizationEnabled, &virt, sizeof(virt), &len))
		return virt ? VirtualizationState::Enabled : VirtualizationState::Disabled;

	return VirtualizationState::Unknown;
}

IntegrityLevel Token::GetIntegrityLevel() const noexcept {
	BYTE buffer[TOKEN_INTEGRITY_LEVEL_MAX_SIZE];
	DWORD len;
	if (!::GetTokenInformation(m_Handle.get(), TokenIntegrityLevel, buffer, sizeof(buffer), &len))
		return IntegrityLevel::Error;

	auto p = (TOKEN_MANDATORY_LABEL*)buffer;
	return (IntegrityLevel)*GetSidSubAuthority(p->Label.Sid, *GetSidSubAuthorityCount(p->Label.Sid) - 1);
}

DWORD Token::GetSessionId() const noexcept {
	DWORD id = -1;
	DWORD len;
	::GetTokenInformation(m_Handle.get(), TokenSessionId, &id, sizeof(id), &len);
	return id;
}

TOKEN_STATISTICS Token::GetStats() const noexcept {
	TOKEN_STATISTICS stats{};
	DWORD len;
	::GetTokenInformation(m_Handle.get(), TokenStatistics, &stats, sizeof(stats), &len);
	return stats;
}

std::vector<TokenGroup> WinSys::Token::EnumGroups(bool caps) const noexcept {
	std::vector<TokenGroup> groups;
	BYTE buffer[1 << 13];
	if (DWORD len; !::GetTokenInformation(m_Handle.get(), caps ? TokenCapabilities : TokenGroups, buffer, sizeof(buffer), &len))
		return groups;

	auto data = (TOKEN_GROUPS*)buffer;
	groups.reserve(data->GroupCount);
	for (ULONG i = 0; i < data->GroupCount; i++) {
		auto const& g = data->Groups[i];
		TokenGroup group;
		Sid sid(g.Sid);
		group.Sid = sid.AsString();
		group.Name = sid.UserName(&group.Use);
		if (group.Name.empty()) {
			group.Name = group.Sid;
			group.Use = SidTypeUnknown;
		}
		group.Attributes = (SidGroupAttributes)g.Attributes;
		groups.push_back(std::move(group));
	}
	return groups;
}

std::vector<TokenPrivilege> Token::EnumPrivileges() const noexcept {
	std::vector<TokenPrivilege> privs;
	BYTE buffer[1 << 12];
	if (DWORD len; !::GetTokenInformation(m_Handle.get(), TokenPrivileges, buffer, sizeof(buffer), &len))
		return privs;

	auto data = (TOKEN_PRIVILEGES*)buffer;
	auto count = data->PrivilegeCount;
	privs.reserve(count);

	WCHAR name[64];
	for (ULONG i = 0; i < count; i++) {
		TokenPrivilege priv;
		auto& p = data->Privileges[i];
		priv.Privilege = p.Luid;
		if (DWORD len = _countof(name); ::LookupPrivilegeName(nullptr, &p.Luid, name, &len))
			priv.Name = name;
		priv.Attributes = p.Attributes;
		privs.push_back(std::move(priv));
	}
	return privs;
}

bool Token::EnablePrivilege(PCWSTR privName, bool enable) const noexcept {
	wil::unique_handle hToken;
	if (!::DuplicateHandle(::GetCurrentProcess(), m_Handle.get(), ::GetCurrentProcess(), hToken.addressof(), 
		TOKEN_ADJUST_PRIVILEGES, FALSE, 0))
		return false;

	bool result = false;
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	if (::LookupPrivilegeValue(nullptr, privName,
		&tp.Privileges[0].Luid)) {
		if (::AdjustTokenPrivileges(hToken.get(), FALSE, &tp, sizeof(tp),
			nullptr, nullptr))
			result = ::GetLastError() == ERROR_SUCCESS;
	}
	return result;
}

