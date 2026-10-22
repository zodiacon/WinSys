#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <wil/resource.h>

//
// Which processes talk to which, over ALPC and RPC, from an ETW real-time session (administrator rights needed):
// - ALPC: the system ALPC provider's send and receive events, matched by message ID (the event header has each side's
//   process). The client is the process that waited for the reply (ALPC-Wait-For-Reply); a message nobody waits for
//   (a datagram) makes its sender the client. Requests and replies are counted alike.
// - RPC: the Microsoft-Windows-RPC provider's call start events. A client call gives the client, the interface, the
//   protocol and the endpoint; the server is the process that started a server call on that endpoint (local endpoints
//   only, and only once one was seen). Calls from other machines aren't counted (the server side doesn't say who).
// Only what's used while the session runs shows: an idle connection appears with its first message.
//

struct _EVENT_RECORD;	// evntcons.h

namespace WinSys {
	enum class IpcKind : uint8_t {
		Alpc,
		Rpc,
	};

	// as the RPC provider numbers them
	enum class RpcProtocol : uint32_t {
		Unknown = 0,
		Tcp = 1,		// ncacn_ip_tcp
		NamedPipe = 2,	// ncacn_np
		Lrpc = 3,		// ncalrpc
		Http = 4,		// ncacn_http
	};

	struct IpcLink {
		IpcKind Kind{ IpcKind::Alpc };
		uint32_t ClientPid{ 0 };
		uint32_t ServerPid{ 0 };	// 0: not known (a remote server, or no server call seen on the endpoint yet)
		// RPC only
		GUID Interface{};
		RpcProtocol Protocol{ RpcProtocol::Unknown };
		std::wstring Endpoint;			// "epmapper", "LRPC-...", "\pipe\lsass"...
		std::wstring NetworkAddress;	// the server's, for a call to another machine
		uint64_t Count{ 0 };	// ALPC messages (requests and replies) or RPC calls
		int64_t FirstSeen{ 0 }, LastSeen{ 0 };	// FILETIME
	};

	class IpcTracker {
	public:
		IpcTracker() = default;
		IpcTracker(IpcTracker const&) = delete;
		IpcTracker& operator=(IpcTracker const&) = delete;
		~IpcTracker();

		// The session is named "<prefix> <process ID>" (as ProcessNetworkTracker's). false on failure, with the error from
		// GetLastError() (ERROR_ACCESS_DENIED when not elevated)
		bool Start(PCWSTR sessionPrefix);
		void Stop();
		[[nodiscard]] bool IsRunning() const;
		// FILETIME; 0 if it isn't running
		[[nodiscard]] int64_t GetStartTime() const;

		// every pair seen since the session started (RPC: per interface and endpoint too), the servers looked up now
		[[nodiscard]] std::vector<IpcLink> GetLinks() const;
		// forgets a process that exited (as a client or a server), as its ID may be reused
		void RemoveProcess(uint32_t pid);

		[[nodiscard]] static PCWSTR ProtocolName(RpcProtocol protocol);
		// a well-known RPC interface's name (the SCM, LSA, the endpoint mapper...), else a COM interface's from the
		// registry (HKCR\Interface); empty if neither knows it. Reads the registry: callers should cache
		[[nodiscard]] static std::wstring GetInterfaceName(GUID const& iface);

	private:
		struct Counter {
			uint64_t Count{ 0 };
			int64_t FirstSeen{ 0 }, LastSeen{ 0 };
			void Add(int64_t now);
		};
		struct RpcKey {
			uint32_t ClientPid;
			GUID Interface;
			RpcProtocol Protocol;
			std::wstring Endpoint, NetworkAddress;
			bool operator==(RpcKey const& other) const;
		};
		struct RpcKeyHash {
			size_t operator()(RpcKey const& key) const noexcept;
		};
		// an ALPC message between its events (on the events' thread only)
		struct PendingMessage {
			uint32_t Sender{ 0 }, Receiver{ 0 }, Client{ 0 };
			uint64_t Tick{ 0 };
		};

		static void WINAPI OnEvent(_EVENT_RECORD* record);
		void OnAlpc(_EVENT_RECORD* record);
		void OnRpc(_EVENT_RECORD* record);
		static DWORD WINAPI ProcessThread(void* param);
		static std::wstring EndpointKey(RpcProtocol protocol, std::wstring const& endpoint);

		std::wstring m_SessionName;
		uint64_t m_Session{ 0 }, m_Trace{ 0 };	// TRACEHANDLE (session control) and PROCESSTRACE_HANDLE (consumer)
		wil::unique_handle m_hThread;
		int64_t m_StartTime{ 0 };
		mutable wil::srwlock m_Lock;
		std::unordered_map<uint64_t, Counter> m_Alpc;	// by client PID << 32 | server PID
		std::unordered_map<RpcKey, Counter, RpcKeyHash> m_Rpc;
		std::unordered_map<std::wstring, uint32_t> m_Endpoints;	// EndpointKey -> the server's PID
		// the events' thread's own
		std::unordered_map<uint32_t, PendingMessage> m_Pending;	// by ALPC message ID
		uint64_t m_LastPrune{ 0 };
	};
}
