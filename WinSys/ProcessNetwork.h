#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <wil/resource.h>

//
// Bytes each process sent and received over TCP and UDP (IPv4 and IPv6), counted from an ETW real-time session on the
// Microsoft-Windows-Kernel-Network provider. Enabling that provider needs administrator rights (Performance Log Users
// can start a session, but not enable it). The counts start when the session does; the events arrive on a background
// thread about once a second.
//

struct _EVENT_RECORD;	// evntcons.h

namespace WinSys {
	class ProcessNetworkTracker {
	public:
		struct Counters {
			uint64_t Sent{ 0 }, Received{ 0 };
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
		// forgets a process that exited, as its ID may be reused
		void RemoveProcess(uint32_t pid);

	private:
		static void WINAPI OnEvent(_EVENT_RECORD* record);
		static DWORD WINAPI ProcessThread(void* param);

		std::wstring m_SessionName;
		uint64_t m_Session{ 0 }, m_Trace{ 0 };	// TRACEHANDLE (session control) and PROCESSTRACE_HANDLE (consumer)
		wil::unique_handle m_hThread;
		mutable wil::srwlock m_Lock;
		std::unordered_map<uint32_t, Counters> m_Counters;
	};
}
