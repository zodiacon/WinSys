#pragma once

#include <string>
#include <vector>
#include <optional>

namespace WinSys {
	// WCT_OBJECT_TYPE
	enum class WaitObjectType {
		CriticalSection = 1, SendMessage, Mutex, Alpc, Com, ThreadWait, ProcessWait, Thread, ComActivation, Unknown,
		SocketIo, SmbIo,
	};

	// WCT_OBJECT_STATUS
	enum class WaitObjectStatus {
		NoAccess = 1, Running, Blocked, PidOnly, PidOnlyRpcss, Owned, NotOwned, Abandoned, Unknown, Error,
	};

	// a node of a wait chain: a thread, or an object a thread waits for (and that's owned by the next thread)
	struct WaitChainNode {
		WaitObjectType Type{ WaitObjectType::Unknown };
		WaitObjectStatus Status{ WaitObjectStatus::Unknown };
		// a thread's
		uint32_t ProcessId{ 0 }, ThreadId{ 0 };
		uint32_t WaitTime{ 0 };		// ms since the thread's wait began (meaningful while it's Blocked)
		uint32_t ContextSwitches{ 0 };
		// an object's
		std::wstring Name;
		bool Alertable{ false };
		bool Timeout{ false };	// the wait has a timeout
	};

	struct WaitChain {
		std::vector<WaitChainNode> Nodes;	// the thread first, then what it waits for, and so on
		bool Cycle{ false };	// a deadlock: the chain leads back to a thread already in it
	};

	//
	// Wait Chain Traversal (WCT): what a thread waits for, who owns that, what that thread waits for... across processes
	// (out-of-process COM, ALPC, critical sections, mutexes, SendMessage, sockets). Synchronous: a chain through a hung
	// process can take a while, so callers run it off the UI thread. Other users' threads need SeDebugPrivilege.
	//
	struct WaitChainTraversal final {
		// nullopt (with the last error) if the chain can't be read
		[[nodiscard]] static std::optional<WaitChain> GetThreadWaitChain(uint32_t threadId);
		[[nodiscard]] static PCWSTR TypeToString(WaitObjectType type);
		[[nodiscard]] static PCWSTR StatusToString(WaitObjectStatus status);
	};
}
