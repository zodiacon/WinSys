#pragma once

namespace WinSys {
	enum class SecurityLogonType {
		UndefinedLogonType,
		Interactive = 2,
		Network,
		Batch,
		Service,
		Proxy,
		Unlock,
		NetworkCleartext,
		NewCredentials,
		RemoteInteractive,
		CachedInteractive,
		CachedRemoteInteractive,
		CachedUnlock
	};

	struct LogonSessionData {
		ULONG         Index;
		LUID          LogonId;
		std::wstring  UserName;
		std::wstring  LogonDomain;
		std::wstring  AuthenticationPackage;
		SecurityLogonType LogonType;
		ULONG         Session;
		BYTE          Sid[SECURITY_MAX_SID_SIZE];
		LARGE_INTEGER LogonTime;

		std::wstring  LogonServer;
		std::wstring  DnsDomainName;
		std::wstring  Upn;
		ULONG         UserFlags;
		LARGE_INTEGER LastSuccessfulLogon;
		LARGE_INTEGER LastFailedLogon;
		ULONG FailedAttemptCountSinceLastSuccessfulLogon;

		std::wstring  LogonScript;
		std::wstring  ProfilePath;
		std::wstring  HomeDirectory;
		std::wstring  HomeDirectoryDrive;

		LARGE_INTEGER LogoffTime;
		LARGE_INTEGER KickOffTime;
		LARGE_INTEGER PasswordLastSet;
		LARGE_INTEGER PasswordCanChange;
		LARGE_INTEGER PasswordMustChange;

		// ERROR_SUCCESS, else why the details couldn't be read (then only Index and LogonId are set): another user's
		// session needs elevation
		DWORD Error{ ERROR_SUCCESS };
	};

	class LsaSecurity final {
	public:
		// every logon session (LsaEnumerateLogonSessions) with its details; inaccessible: also those whose details can't
		// be read (another user's, unless elevated), with Error set, else they're left out
		static std::vector<LogonSessionData> EnumLogonSessions(bool inaccessible = false);
		// one logon session (its Index is 0); access denied unless it's the caller's or the caller is elevated
		static std::optional<LogonSessionData> GetLogonSessionData(LUID const& logonId);
		static std::wstring GetUserNameByLogonSession(PLUID sessionId);
		// "Interactive", "Network", "Remote interactive"...; "System" for none (the SYSTEM session's)
		[[nodiscard]] static PCWSTR LogonTypeName(SecurityLogonType type);
	};
}

