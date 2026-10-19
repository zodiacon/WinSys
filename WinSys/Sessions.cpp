#include "pch.h"
#include <WtsApi32.h>
#include "Sessions.h"

#pragma comment(lib, "wtsapi32")

using namespace WinSys;

void SessionManager::GetDetails(SessionInfo& session) {
	DWORD bytes;
	WTSINFOW* wtsInfo = nullptr;
	if (::WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session.Id, WTSSessionInfo, (LPWSTR*)&wtsInfo, &bytes)) {
		session.LogonTime = wtsInfo->LogonTime.QuadPart;
		session.ConnectTime = wtsInfo->ConnectTime.QuadPart;
		session.DisconnectTime = wtsInfo->DisconnectTime.QuadPart;
		::WTSFreeMemory(wtsInfo);
	}
	// only a remote session has a client; the console and sessions no one is logged on to have none
	if (session.UserName.empty() || session.Id == ::WTSGetActiveConsoleSessionId())
		return;
	PWSTR client = nullptr;
	if (::WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session.Id, WTSClientName, &client, &bytes)) {
		session.ClientName = client;
		::WTSFreeMemory(client);
	}
}

std::vector<SessionInfo> SessionManager::EnumSessions(bool details) {
	std::vector<SessionInfo> sessions;
	DWORD level = 1, count = 0;
	PWTS_SESSION_INFO_1 info = nullptr;
	if (!::WTSEnumerateSessionsEx(WTS_CURRENT_SERVER_HANDLE, &level, 0, &info, &count))
		return sessions;

	sessions.reserve(count);
	for (DWORD i = 0; i < count; i++) {
		auto& s = info[i];
		if (s.State == WTSListen)
			continue;

		SessionInfo session{};
		session.Id = s.SessionId;
		session.State = static_cast<SessionState>(s.State);
		session.Name = s.pSessionName ? s.pSessionName : L"";
		session.UserName = s.pUserName ? s.pUserName : L"";
		session.Domain = s.pDomainName ? s.pDomainName : L"";
		if (details)
			GetDetails(session);
		sessions.push_back(std::move(session));
	}
	::WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, info, count);
	return sessions;
}

bool SessionManager::Disconnect(uint32_t sessionId, bool wait) {
	return ::WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, sessionId, wait);
}

bool SessionManager::Logoff(uint32_t sessionId, bool wait) {
	return ::WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, sessionId, wait);
}
