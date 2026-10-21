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
	DEFINE_ENUM_FLAG_OPERATORS(TokenAccessMask);

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

	enum class ElevationType {
		Default = 1,	// no linked token (UAC off, or a standard user, or a service)
		Full,			// the elevated half of a split token
		Limited,		// the filtered half of a split token
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
		// token ID, logon session (AuthenticationId), modified ID, type, impersonation level, dynamic memory, counts
		TOKEN_STATISTICS GetStats() const noexcept;
		// caps: the AppContainer capabilities instead of the groups
		std::vector<TokenGroup> EnumGroups(bool caps = false) const noexcept;
		std::vector<TokenPrivilege> EnumPrivileges() const noexcept;

		Sid GetOwner() const noexcept;
		Sid GetPrimaryGroup() const noexcept;
		std::optional<ElevationType> GetElevationType() const noexcept;
		std::optional<bool> HasUIAccess() const noexcept;
		std::optional<bool> IsSandboxInert() const noexcept;
		// TOKEN_MANDATORY_POLICY_NO_WRITE_UP, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN
		std::optional<uint32_t> GetMandatoryPolicy() const noexcept;
		// has restricted SIDs (a restricted token)
		bool IsRestricted() const noexcept;
		// filtered: restricted, or without some privileges or groups the original had (TokenHasRestrictions)
		std::optional<bool> HasRestrictions() const noexcept;
		bool IsAppContainer() const noexcept;
		// an invalid Sid for a token not in an AppContainer
		Sid GetAppContainerSid() const noexcept;
		std::optional<uint32_t> GetAppContainerNumber() const noexcept;
		// needs TokenAccessMask::QuerySource
		std::optional<TOKEN_SOURCE> GetSource() const noexcept;
		// the logon session that created the token's logon session
		std::optional<LUID> GetOrigin() const noexcept;
		// the protection level of a protected process's token; an invalid Sid otherwise
		Sid GetTrustLevel() const noexcept;

	private:
		wil::unique_handle m_Handle;
	};
}

