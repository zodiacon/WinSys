#include "pch.h"
#include "WaitChain.h"
#include <wct.h>

#pragma comment(lib, "advapi32")

using namespace WinSys;

namespace {
	// COM waits are followed only with ole32's callbacks registered (once per process, before the first session)
	void RegisterComCallbacks() {
		static bool registered = [] {
			auto hOle = ::LoadLibrary(L"ole32.dll");
			if (!hOle)
				return false;
			auto callState = reinterpret_cast<PCOGETCALLSTATE>(::GetProcAddress(hOle, "CoGetCallState"));
			auto activationState = reinterpret_cast<PCOGETACTIVATIONSTATE>(::GetProcAddress(hOle, "CoGetActivationState"));
			if (!callState || !activationState)
				return false;
			::RegisterWaitChainCOMCallback(callState, activationState);
			return true;
		}();
		(void)registered;
	}
}

std::optional<WaitChain> WaitChainTraversal::GetThreadWaitChain(uint32_t threadId) {
	RegisterComCallbacks();
	// synchronous: no callback
	auto session = ::OpenThreadWaitChainSession(0, nullptr);
	if (!session)
		return std::nullopt;

	WAITCHAIN_NODE_INFO nodes[WCT_MAX_NODE_COUNT];
	DWORD count = WCT_MAX_NODE_COUNT;
	BOOL cycle = FALSE;
	auto ok = ::GetThreadWaitChain(session, 0, WCTP_GETINFO_ALL_FLAGS, threadId, &count, nodes, &cycle);
	auto error = ::GetLastError();
	::CloseThreadWaitChainSession(session);
	if (!ok) {
		::SetLastError(error);
		return std::nullopt;
	}

	// a thread's WaitTime is the clock tick its wait began on (the kernel's tick count), not a duration: the elapsed time
	// is the current tick count (from GetTickCount64 and the tick's length) minus that, in the 32 bits WCT keeps
	DWORD adjustment, increment = 0;
	BOOL disabled;
	if (!::GetSystemTimeAdjustment(&adjustment, &increment, &disabled) || increment == 0)
		increment = 156250;	// 15.625 ms, in 100 ns units
	auto nowTicks = (uint32_t)(::GetTickCount64() * 10000 / increment);

	WaitChain chain;
	chain.Cycle = cycle;
	for (DWORD i = 0; i < (std::min)(count, (DWORD)WCT_MAX_NODE_COUNT); i++) {
		auto& n = nodes[i];
		WaitChainNode node;
		node.Type = (WaitObjectType)n.ObjectType;
		node.Status = (WaitObjectStatus)n.ObjectStatus;
		if (n.ObjectType == WctThreadType) {
			node.ProcessId = n.ThreadObject.ProcessId;
			node.ThreadId = n.ThreadObject.ThreadId;
			node.WaitTime = (uint32_t)((uint64_t)(uint32_t)(nowTicks - n.ThreadObject.WaitTime) * increment / 10000);
			node.ContextSwitches = n.ThreadObject.ContextSwitches;
		}
		else {
			node.Name.assign(n.LockObject.ObjectName, wcsnlen(n.LockObject.ObjectName, WCT_OBJNAME_LENGTH));
			node.Alertable = n.LockObject.Alertable;
			node.Timeout = n.LockObject.Timeout.QuadPart != 0;
		}
		chain.Nodes.push_back(std::move(node));
	}
	return chain;
}

PCWSTR WaitChainTraversal::TypeToString(WaitObjectType type) {
	using enum WaitObjectType;
	switch (type) {
		case CriticalSection: return L"Critical Section";
		case SendMessage: return L"SendMessage";
		case Mutex: return L"Mutex";
		case Alpc: return L"ALPC";
		case Com: return L"COM";
		case ThreadWait: return L"Thread Wait";
		case ProcessWait: return L"Process Wait";
		case Thread: return L"Thread";
		case ComActivation: return L"COM Activation";
		case SocketIo: return L"Socket I/O";
		case SmbIo: return L"SMB I/O";
	}
	return L"Unknown";
}

PCWSTR WaitChainTraversal::StatusToString(WaitObjectStatus status) {
	using enum WaitObjectStatus;
	switch (status) {
		case NoAccess: return L"No Access";
		case Running: return L"Running";
		case Blocked: return L"Blocked";
		case PidOnly: return L"Process Only";
		case PidOnlyRpcss: return L"Process Only (RPCSS)";
		case Owned: return L"Owned";
		case NotOwned: return L"Not Owned";
		case Abandoned: return L"Abandoned";
		case Error: return L"Error";
	}
	return L"Unknown";
}
