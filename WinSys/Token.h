#pragma once

#include "Sid.h"
#include "Processes.h"
#include "Enums.h"

namespace WinSys {
	enum class TokenAccessMask : uint32_t {
		Query = TOKEN_QUERY,
		QuerySource = TOKEN_QUERY_SOURCE,
		AssignPrimary = TOKEN_ASSIGN_PRIMARY,
		AdjustPrivileges = TOKEN_ADJUST_PRIVILEGES,
		AdjustDefault = TOKEN_ADJUST_DEFAULT,
		AdjustGroups = TOKEN_ADJUST_GROUPS,
		AdjustSessionId = TOKEN_ADJUST_SESSIONID,
	};

	enum class SidGroupAttributes : uint32_t {
		Enabled = SE_GROUP_ENABLED,
		DefaultEnabled = SE_GROUP_ENABLED_BY_DEFAULT,
		Integrity = SE_GROUP_INTEGRITY,
		IntegrityEnabled = SE_GROUP_INTEGRITY_ENABLED,
		LogonId = SE_GROUP_LOGON_ID,
		Mandatory = SE_GROUP_MANDATORY,
		Owner = SE_GROUP_OWNER,
		DomainLocal = SE_GROUP_RESOURCE,
		DenyOnly = SE_GROUP_USE_FOR_DENY_ONLY
	};
	DEFINE_ENUM_FLAG_OPERATORS(WinSys::SidGroupAttributes);

	struct TokenGroup {
		std::wstring Name;
		std::wstring Sid;
		SID_NAME_USE Use;
		SidGroupAttributes Attributes;
	};

	struct TokenPrivilege {
		LUID Privilege;
		std::wstring Name;
		uint32_t Attributes;
	};

	class Token final {
	public:
		explicit Token(HANDLE hToken) noexcept;
		bool OpenProcessToken(DWORD pid, TokenAccessMask access) noexcept;
		Token(HANDLE hProcess, TokenAccessMask access) noexcept;
		static std::unique_ptr<Token> Open(DWORD pid, TokenAccessMask access = TokenAccessMask::Query);

		bool EnablePrivilege(PCWSTR name, bool enable) const noexcept;

		std::pair<std::wstring, Sid> GetUserNameAndSid() const;
		std::wstring GetUserName() const;

		bool IsValid() const noexcept;
		operator bool() const noexcept;
		bool IsElevated() const noexcept;
		VirtualizationState GetVirtualizationState() const noexcept;
		IntegrityLevel GetIntegrityLevel() const noexcept;
		DWORD GetSessionId() const noexcept;
		TOKEN_STATISTICS GetStats() const noexcept;
		std::vector<TokenGroup> EnumGroups(bool caps = false) const noexcept;
		std::vector<TokenPrivilege> EnumPrivileges() const noexcept;

	private:
		wil::unique_handle m_Handle;
	};
}

