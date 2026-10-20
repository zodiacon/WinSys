#include "pch.h"
#include "Token.h"
#include <assert.h>

using namespace WinSys;

namespace {
	// a variable-size class, in a buffer of its size
	std::unique_ptr<BYTE[]> QueryVariable(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass) {
		ULONG len = 0;
		::NtQueryInformationToken(hToken, infoClass, nullptr, 0, &len);
		if (len == 0)
			return nullptr;
		for (int i = 0; i < 3; i++) {
			// operator new's alignment suits the structures
			auto buffer = std::make_unique<BYTE[]>(len);
			auto status = ::NtQueryInformationToken(hToken, infoClass, buffer.get(), len, &len);
			if (NT_SUCCESS(status))
				return buffer;
			if (status != STATUS_BUFFER_TOO_SMALL)
				break;
		}
		return nullptr;
	}

	template<typename T>
	std::optional<T> QueryFixed(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass) {
		T value{};
		ULONG len;
		if (!NT_SUCCESS(::NtQueryInformationToken(hToken, infoClass, &value, sizeof(value), &len)))
			return std::nullopt;
		return value;
	}

	// the SID a variable-size class starts with (TOKEN_OWNER, TOKEN_PRIMARY_GROUP, ...)
	Sid QuerySid(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass) {
		auto buffer = QueryVariable(hToken, infoClass);
		auto sid = buffer ? *reinterpret_cast<PSID*>(buffer.get()) : nullptr;
		return sid ? Sid(sid) : Sid();
	}
}

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
	// the token's own security decides; limited access to the process is enough to open it
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
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
	if (NT_SUCCESS(::NtQueryInformationToken(m_Handle.get(), TokenUser, buffer, sizeof(buffer), &len))) {
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
	::NtQueryInformationToken(m_Handle.get(), TokenElevation, &elevated, sizeof(elevated), &len);
	return elevated ? true : false;
}

VirtualizationState Token::GetVirtualizationState() const noexcept {
	ULONG virt = 0;
	DWORD len;
	if (!NT_SUCCESS(::NtQueryInformationToken(m_Handle.get(), TokenVirtualizationAllowed, &virt, sizeof(virt), &len)))
		return VirtualizationState::Unknown;

	if (!virt)
		return VirtualizationState::NotAllowed;

	if (NT_SUCCESS(::NtQueryInformationToken(m_Handle.get(), TokenVirtualizationEnabled, &virt, sizeof(virt), &len)))
		return virt ? VirtualizationState::Enabled : VirtualizationState::Disabled;

	return VirtualizationState::Unknown;
}

IntegrityLevel Token::GetIntegrityLevel() const noexcept {
	BYTE buffer[TOKEN_INTEGRITY_LEVEL_MAX_SIZE];
	DWORD len;
	if (!NT_SUCCESS(::NtQueryInformationToken(m_Handle.get(), TokenIntegrityLevel, buffer, sizeof(buffer), &len)))
		return IntegrityLevel::Error;

	auto p = (TOKEN_MANDATORY_LABEL*)buffer;
	return (IntegrityLevel)*GetSidSubAuthority(p->Label.Sid, *GetSidSubAuthorityCount(p->Label.Sid) - 1);
}

DWORD Token::GetSessionId() const noexcept {
	DWORD id = -1;
	DWORD len;
	::NtQueryInformationToken(m_Handle.get(), TokenSessionId, &id, sizeof(id), &len);
	return id;
}

TOKEN_STATISTICS Token::GetStats() const noexcept {
	TOKEN_STATISTICS stats{};
	DWORD len;
	::NtQueryInformationToken(m_Handle.get(), TokenStatistics, &stats, sizeof(stats), &len);
	return stats;
}

std::vector<TokenGroup> WinSys::Token::EnumGroups(bool caps) const noexcept {
	std::vector<TokenGroup> groups;
	// a domain account's token can have hundreds of groups
	auto buffer = QueryVariable(m_Handle.get(), caps ? TokenCapabilities : TokenGroups);
	if (!buffer)
		return groups;

	auto data = (TOKEN_GROUPS*)buffer.get();
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
	auto buffer = QueryVariable(m_Handle.get(), TokenPrivileges);
	if (!buffer)
		return privs;

	auto data = (TOKEN_PRIVILEGES*)buffer.get();
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

Sid Token::GetOwner() const noexcept {
	return QuerySid(m_Handle.get(), TokenOwner);
}

Sid Token::GetPrimaryGroup() const noexcept {
	return QuerySid(m_Handle.get(), TokenPrimaryGroup);
}

std::optional<ElevationType> Token::GetElevationType() const noexcept {
	auto type = QueryFixed<TOKEN_ELEVATION_TYPE>(m_Handle.get(), TokenElevationType);
	return type ? std::optional(static_cast<ElevationType>(*type)) : std::nullopt;
}

std::optional<bool> Token::HasUIAccess() const noexcept {
	auto value = QueryFixed<ULONG>(m_Handle.get(), TokenUIAccess);
	return value ? std::optional(*value != 0) : std::nullopt;
}

std::optional<bool> Token::IsSandboxInert() const noexcept {
	auto value = QueryFixed<ULONG>(m_Handle.get(), TokenSandBoxInert);
	return value ? std::optional(*value != 0) : std::nullopt;
}

std::optional<uint32_t> Token::GetMandatoryPolicy() const noexcept {
	auto policy = QueryFixed<TOKEN_MANDATORY_POLICY>(m_Handle.get(), TokenMandatoryPolicy);
	return policy ? std::optional<uint32_t>(policy->Policy) : std::nullopt;
}

bool Token::IsRestricted() const noexcept {
	auto buffer = QueryVariable(m_Handle.get(), TokenRestrictedSids);
	return buffer && reinterpret_cast<TOKEN_GROUPS*>(buffer.get())->GroupCount > 0;
}

std::optional<bool> Token::HasRestrictions() const noexcept {
	auto value = QueryFixed<ULONG>(m_Handle.get(), TokenHasRestrictions);
	return value ? std::optional(*value != 0) : std::nullopt;
}

bool Token::IsAppContainer() const noexcept {
	auto value = QueryFixed<ULONG>(m_Handle.get(), TokenIsAppContainer);
	return value && *value;
}

Sid Token::GetAppContainerSid() const noexcept {
	return QuerySid(m_Handle.get(), TokenAppContainerSid);
}

std::optional<uint32_t> Token::GetAppContainerNumber() const noexcept {
	auto value = QueryFixed<ULONG>(m_Handle.get(), TokenAppContainerNumber);
	return value ? std::optional<uint32_t>(*value) : std::nullopt;
}

std::optional<TOKEN_SOURCE> Token::GetSource() const noexcept {
	return QueryFixed<TOKEN_SOURCE>(m_Handle.get(), TokenSource);
}

std::optional<LUID> Token::GetOrigin() const noexcept {
	auto origin = QueryFixed<TOKEN_ORIGIN>(m_Handle.get(), TokenOrigin);
	return origin ? std::optional(origin->OriginatingLogonSession) : std::nullopt;
}

Sid Token::GetTrustLevel() const noexcept {
	return QuerySid(m_Handle.get(), TokenProcessTrustLevel);
}
