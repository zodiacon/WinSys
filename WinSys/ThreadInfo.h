#pragma once

#include <string>
#include "Keys.h"

namespace WinSys {
	enum class ThreadState : uint32_t {
		Initialized = 0,
		Ready = 1,
		Running = 2,
		Standby = 3,
		Terminated = 4,
		Waiting = 5,
		Transition = 6,
		DeferredReady = 7,
		GateWaitObsolete = 8,
		WaitingForProcessInSwap = 9
	};

	enum class WaitReason : uint32_t {
		Executive,
		FreePage,
		PageIn,
		PoolAllocation,
		DelayExecution,
		Suspended,
		UserRequest,
		WrExecutive,
		WrFreePage,
		WrPageIn,
		WrPoolAllocation,
		WrDelayExecution,
		WrSuspended,
		WrUserRequest,
		WrEventPair,
		WrQueue,
		WrLpcReceive,
		WrLpcReply,
		WrVirtualMemory,
		WrPageOut,
		WrRendezvous,
		WrKeyedEvent,
		WrTerminated,
		WrProcessInSwap,
		WrCpuRateControl,
		WrCalloutStack,
		WrKernel,
		WrResource,
		WrPushLock,
		WrMutex,
		WrQuantumEnd,
		WrDispatchInt,
		WrPreempted,
		WrYieldExecution,
		WrFastMutex,
		WrGuardedMutex,
		WrRundown,
		WrAlertByThreadId,
		WrDeferredPreempt,
		MaximumWaitReason
	};

	struct ThreadInfo {
		template<typename TProcessInfo, typename TThreadInfo>
		friend class ProcessManager;

		const SYSTEM_EXTENDED_THREAD_INFORMATION* ExtendedInfo{ nullptr };
		const SYSTEM_THREAD_INFORMATION* NativeInfo{ nullptr };

		const std::wstring& GetProcessImageName() const {
			return m_ProcessName;
		}

		uint32_t Id, ProcessId;
		ThreadState GetThreadState() const;
		WaitReason GetWaitReason() const;

		int32_t CPU;

		ProcessOrThreadKey Key;

	private:
		std::wstring m_ProcessName;
	};
}

