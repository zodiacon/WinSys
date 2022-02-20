#pragma once

#ifdef WINSYS_NAMESPACE
namespace WinSys {
#endif
	enum class ProcessAccessMask : uint32_t {
		None = 0,
		AllAccess = PROCESS_ALL_ACCESS,
		CreateThread = PROCESS_CREATE_THREAD,
		DuplicateHandle = PROCESS_DUP_HANDLE,
		VmRead = PROCESS_VM_READ,
		VmWrite = PROCESS_VM_WRITE,
		VmOperation = PROCESS_VM_OPERATION,
		Terminate = PROCESS_TERMINATE,
		QueryInformation = PROCESS_QUERY_INFORMATION,
		QueryLimitedInformation = PROCESS_QUERY_LIMITED_INFORMATION,
		SuspendResume = PROCESS_SUSPEND_RESUME,
		Synchonize = SYNCHRONIZE,
		GenericWrite = GENERIC_WRITE,
		GenericRead = GENERIC_READ,
		GenericAll = GENERIC_ALL,
	};
#ifdef WINSYS_NAMESPACE
	DEFINE_ENUM_FLAG_OPERATORS(WinSys::ProcessAccessMask);
#else
	DEFINE_ENUM_FLAG_OPERATORS(ProcessAccessMask);
#endif

	enum class PriorityClass {
		Normal = NORMAL_PRIORITY_CLASS,
		BelowNormal = BELOW_NORMAL_PRIORITY_CLASS,
		AboveNormal = ABOVE_NORMAL_PRIORITY_CLASS,
		Idle = IDLE_PRIORITY_CLASS,
		High = HIGH_PRIORITY_CLASS,
		Realtime = REALTIME_PRIORITY_CLASS,
		Unknown = 0,
	};

	enum class IntegrityLevel : uint32_t {
		Untrusted = 0,
		Low = SECURITY_MANDATORY_LOW_RID,
		Medium = SECURITY_MANDATORY_MEDIUM_RID,
		MediumPlus = SECURITY_MANDATORY_MEDIUM_PLUS_RID,
		High = SECURITY_MANDATORY_HIGH_RID,
		System = SECURITY_MANDATORY_SYSTEM_RID,
		Protected = SECURITY_MANDATORY_PROTECTED_PROCESS_RID,
		Error = 0xffffffff,
	};

	enum class ThreadPriorityLevel {
		Idle = THREAD_PRIORITY_IDLE,
		Lowest = THREAD_PRIORITY_LOWEST,
		BelowNormal = THREAD_PRIORITY_BELOW_NORMAL,
		Normal = THREAD_PRIORITY_NORMAL,
		AboveNormal = THREAD_PRIORITY_ABOVE_NORMAL,
		Highest = THREAD_PRIORITY_HIGHEST,
		TimeCritical = THREAD_PRIORITY_TIME_CRITICAL
	};

	enum class ThreadAccessMask : uint32_t {
		Synchronize = SYNCHRONIZE,
		DirectImpersonation = THREAD_DIRECT_IMPERSONATION,
		GetContext = THREAD_GET_CONTEXT,
		SetContext = THREAD_SET_CONTEXT,
		SetInformation = THREAD_SET_INFORMATION,
		Impersonate = THREAD_IMPERSONATE,
		QueryInformation = THREAD_QUERY_INFORMATION,
		QueryLimitedInformation = THREAD_QUERY_LIMITED_INFORMATION,
		SetLimitedInformation = THREAD_SET_LIMITED_INFORMATION,
		SetThreadToken = THREAD_SET_THREAD_TOKEN,
		SuspendResume = THREAD_SUSPEND_RESUME,
		Terminate = THREAD_TERMINATE,
		SystemSecurity = ACCESS_SYSTEM_SECURITY,
		AllAccess = THREAD_ALL_ACCESS
	};

	enum class IoPriorityHint {
		Unknown = -1,
		VeryLow = 0,
		Low,
		Normal,
		High,
		Critical
	};

#ifdef WINSYS_NAMESPACE
}
#endif
