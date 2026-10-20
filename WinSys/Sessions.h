#pragma once

#include <string>
#include <vector>
#include <cstdint>

//
// Terminal Services (WTS) sessions: the console, remote desktop sessions and session 0 (services).
// The library links wtsapi32.lib itself.
//

namespace WinSys {
	enum class SessionState : uint32_t {	// WTS_CONNECTSTATE_CLASS
		Active, Connected, ConnectQuery, Shadow, Disconnected, Idle, Listen, Reset, Down, Init
	};

	struct SessionInfo {
		uint32_t Id;
		SessionState State;
		std::wstring Name;			// the window station: "Console", "RDP-Tcp#3", "Services"
		std::wstring UserName, Domain;	// empty if no one is logged on
		// the details (see SessionManager::GetDetails)
		std::wstring ClientName;	// the remote computer, for a remote session
		int64_t LogonTime, ConnectTime, DisconnectTime;	// FILETIME (UTC), 0 if not known
	};

	struct SessionManager final {
		// Sessions on this computer, without the listeners (State Listen). Without details, only the ID, state,
		// name and user are filled, which is cheap: the details take queries to the session that raise (and handle)
		// RPC exceptions for sessions without a client, so callers that poll should get them only when a session changes.
		[[nodiscard]] static std::vector<SessionInfo> EnumSessions(bool details = true);
		static void GetDetails(SessionInfo& session);
		// returns false on failure, with the error from GetLastError()
		static bool Disconnect(uint32_t sessionId, bool wait = false);
		static bool Logoff(uint32_t sessionId, bool wait = false);
	};
}
