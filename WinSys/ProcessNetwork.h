#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <wil/resource.h>

//
// Bytes each process sent and received over TCP and UDP (IPv4 and IPv6), counted from an ETW real-time session on the
// Microsoft-Windows-Kernel-Network provider. Enabling that provider needs administrator rights (Performance Log Users
// can start a session, but not enable it). The counts start when the session does; the events arrive on a background
// thread about once a second. The same events are counted per connection too (their addresses and ports).
//

struct _EVENT_RECORD;	// evntcons.h

namespace WinSys {
	class ProcessNetworkTracker {
	public:
		struct Counters {
			uint64_t Sent{ 0 }, Received{ 0 };
		};

		// a connection as the events tell it: TCP by both ends; UDP by its local port only (an endpoint's datagrams go
		// to and come from anywhere, and it's often bound to the unspecified address), its addresses and remote port
		// zero. An IPv4 address is in the first 4 bytes, in network order (as WinSys::Connection has it); ports are in
		// host order
		struct ConnectionId {
			uint32_t Pid{ 0 };
			bool Udp{ false }, V6{ false };
			std::array<uint8_t, 16> LocalAddress{}, RemoteAddress{};
			uint16_t LocalPort{ 0 }, RemotePort{ 0 };

			bool operator==(ConnectionId const&) const = default;
		};
		struct ConnectionIdHash {
			size_t operator()(ConnectionId const& id) const noexcept;
		};

		ProcessNetworkTracker() = default;
		ProcessNetworkTracker(ProcessNetworkTracker const&) = delete;
		ProcessNetworkTracker& operator=(ProcessNetworkTracker const&) = delete;
		~ProcessNetworkTracker();

		// The session is named "<prefix> <process ID>", so instances don't share it. Sessions with that prefix left over
		// from processes that exited without stopping them (they crashed) are stopped first.
		// Returns false on failure, with the error from GetLastError() (ERROR_ACCESS_DENIED when not elevated).
		bool Start(PCWSTR sessionPrefix);
		void Stop();
		[[nodiscard]] bool IsRunning() const;

		[[nodiscard]] Counters GetCounters(uint32_t pid) const;
		// forgets a process that exited (and its connections), as its ID may be reused
		void RemoveProcess(uint32_t pid);

		// the bytes over a connection since the session started (or since it was first seen, if later)
		[[nodiscard]] Counters GetConnectionCounters(ConnectionId const& id) const;
		// forgets the connections not in live (closed ones), so the counts don't pile up
		void RetainConnections(std::vector<ConnectionId> const& live);

	private:
		static void WINAPI OnEvent(_EVENT_RECORD* record);
		static DWORD WINAPI ProcessThread(void* param);

		std::wstring m_SessionName;
		uint64_t m_Session{ 0 }, m_Trace{ 0 };	// TRACEHANDLE (session control) and PROCESSTRACE_HANDLE (consumer)
		wil::unique_handle m_hThread;
		mutable wil::srwlock m_Lock;
		std::unordered_map<uint32_t, Counters> m_Counters;
		std::unordered_map<ConnectionId, Counters, ConnectionIdHash> m_Connections;
	};
}
