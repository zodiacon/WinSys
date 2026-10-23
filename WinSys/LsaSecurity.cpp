#include "pch.h"
#include "LsaSecurity.h"

#pragma comment(lib, "Secur32")

using namespace WinSys;

static void LsaStringToWstring(LSA_UNICODE_STRING const& lsa, std::wstring& str) {
	str.assign(lsa.Buffer, lsa.Length / sizeof(WCHAR));
}

static LogonSessionData ToSessionData(SECURITY_LOGON_SESSION_DATA const* data) {
	LogonSessionData sd{};
	sd.LogonId = data->LogonId;
	LsaStringToWstring(data->AuthenticationPackage, sd.AuthenticationPackage);
	LsaStringToWstring(data->DnsDomainName, sd.DnsDomainName);
	LsaStringToWstring(data->HomeDirectory, sd.HomeDirectory);
	LsaStringToWstring(data->HomeDirectoryDrive, sd.HomeDirectoryDrive);
	LsaStringToWstring(data->LogonDomain, sd.LogonDomain);
	LsaStringToWstring(data->LogonScript, sd.LogonScript);
	LsaStringToWstring(data->LogonServer, sd.LogonServer);
	LsaStringToWstring(data->UserName, sd.UserName);
	LsaStringToWstring(data->Upn, sd.Upn);
	LsaStringToWstring(data->ProfilePath, sd.ProfilePath);

	sd.LogoffTime = data->LogoffTime;
	sd.LogonTime = data->LogonTime;
	sd.LastFailedLogon = data->LastLogonInfo.LastFailedLogon;
	sd.LastSuccessfulLogon = data->LastLogonInfo.LastSuccessfulLogon;
	sd.FailedAttemptCountSinceLastSuccessfulLogon = data->LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon;
	sd.KickOffTime = data->KickOffTime;
	sd.UserFlags = data->UserFlags;
	sd.LogonType = (SecurityLogonType)data->LogonType;
	if (data->Sid)
		::CopySid(_countof(sd.Sid), (PSID)sd.Sid, data->Sid);
	else
		::memset(sd.Sid, 0, sizeof(sd.Sid));
	sd.Session = data->Session;
	sd.PasswordCanChange = data->PasswordCanChange;
	sd.PasswordLastSet = data->PasswordLastSet;
	sd.PasswordMustChange = data->PasswordMustChange;

	return sd;
}

std::vector<LogonSessionData> LsaSecurity::EnumLogonSessions(bool inaccessible) {
	std::vector<LogonSessionData> sessions;

	LUID* luid;
	ULONG count;
	if (!NT_SUCCESS(::LsaEnumerateLogonSessions(&count, &luid)))
		return sessions;

	sessions.reserve(count);
	for (ULONG i = 0; i < count; i++) {
		SECURITY_LOGON_SESSION_DATA* data;
		auto status = ::LsaGetLogonSessionData(luid + i, &data);
		if (NT_SUCCESS(status)) {
			auto sd = ToSessionData(data);
			sd.Index = i + 1;
			sessions.emplace_back(std::move(sd));

			::LsaFreeReturnBuffer(data);
		}
		else if (inaccessible) {
			LogonSessionData sd{};
			sd.Index = i + 1;
			sd.LogonId = luid[i];
			sd.Error = ::LsaNtStatusToWinError(status);
			sessions.emplace_back(std::move(sd));
		}
	}

	::LsaFreeReturnBuffer(luid);
	return sessions;
}

std::optional<LogonSessionData> LsaSecurity::GetLogonSessionData(LUID const& logonId) {
	SECURITY_LOGON_SESSION_DATA* data;
	auto luid = logonId;
	if (!NT_SUCCESS(::LsaGetLogonSessionData(&luid, &data)))
		return std::nullopt;
	auto sd = ToSessionData(data);
	::LsaFreeReturnBuffer(data);
	return sd;
}

PCWSTR LsaSecurity::LogonTypeName(SecurityLogonType type) {
	switch (type) {
		case SecurityLogonType::Interactive: return L"Interactive";
		case SecurityLogonType::Network: return L"Network";
		case SecurityLogonType::Batch: return L"Batch";
		case SecurityLogonType::Service: return L"Service";
		case SecurityLogonType::Proxy: return L"Proxy";
		case SecurityLogonType::Unlock: return L"Unlock";
		case SecurityLogonType::NetworkCleartext: return L"Network (cleartext)";
		case SecurityLogonType::NewCredentials: return L"New credentials";
		case SecurityLogonType::RemoteInteractive: return L"Remote interactive";
		case SecurityLogonType::CachedInteractive: return L"Cached interactive";
		case SecurityLogonType::CachedRemoteInteractive: return L"Cached remote interactive";
		case SecurityLogonType::CachedUnlock: return L"Cached unlock";
	}
	return L"System";
}

std::wstring LsaSecurity::GetUserNameByLogonSession(PLUID sessionId) {
	SECURITY_LOGON_SESSION_DATA* data;
	if (0 == ::LsaGetLogonSessionData(sessionId, &data)) {
		std::wstring username(data->UserName.Buffer, data->UserName.Length / sizeof(WCHAR));
		LsaFreeReturnBuffer(data);
		return username;
	}
	return L"";
}

LSA_HANDLE OpenLsaHandle(DWORD lsaAccess) {
	LSA_HANDLE hPolicy = nullptr;
	LSA_OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	auto status = ::LsaOpenPolicy(nullptr, &oa, lsaAccess, &hPolicy);
	::SetLastError(::RtlNtStatusToDosError(status));
	return hPolicy;
}

