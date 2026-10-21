#pragma once

#include <string>
#include "Enums.h"

namespace WinSys {
	struct CpuNumber {
		uint16_t Group;
		uint8_t Number;
	};

	enum class ComFlags : uint32_t {
		None = 0,
		LocalTid = 0x01,
		UuidInitialized = 0x02,
		InThreadDetach = 0x04,
		ChannelInitialized = 0x08,
		WowThread = 0x10,
		ThreadUninitializing = 0x20,
		DisableOle1DDE = 0x40,
		STA = 0x80,
		MTA = 0x100,
		Impersonating = 0x200,
		DisableEventLogger = 0x400,
		InNeutralApartment = 0x800,
		DispatchThread = 0x1000,
		HostThread = 0x2000,
		AllowCoInit = 0x4000,
		PendingUninit = 0x8000,
		FirstMTAInit = 0x10000,
		FirstNTAInit = 0x20000,
		ApartmentInitializing = 0x40000,
		UIMessageInModalLoop = 0x80000,
		MarshallingErrorObject = 0x100000,
		WinRTInitialize = 0x200000,
		ASTA = 0x400000,
		InShutdownCallbacks = 0x800000,
		PointerInputBlocked = 0x1000000,
		InActivationFilter = 0x2000000,
		ASTAtoASTAExempQuirk = 0x4000000,
		ASTAtoASTAExempProxy = 0x8000000,
		ASTAtoASTAExempIndoubt = 0x10000000,
		DetectedUserInit = 0x20000000,
		BridgeSTA = 0x40000000,
		MainInitializing = 0x80000000,

		Error = 0xffffffff
	};
#ifdef WINSYS_NAMESPACE
	DEFINE_ENUM_FLAG_OPERATORS(WinSys::ComFlags);
#else
	DEFINE_ENUM_FLAG_OPERATORS(ComFlags);
#endif
	class Thread final {
	public:
		static std::unique_ptr<Thread> OpenById(uint32_t tid, ThreadAccessMask accessMask = ThreadAccessMask::QueryInformation);
		explicit Thread(HANDLE handle, bool own = false);
		bool Open(uint32_t tid, ThreadAccessMask accessMask = ThreadAccessMask::QueryInformation) noexcept;
		~Thread() noexcept;

		HANDLE Handle() const noexcept {
			return m_handle;
		}

		operator bool() const noexcept {
			return IsValid();
		}
		bool IsValid() const noexcept;

		ThreadPriorityLevel GetPriority() const noexcept;
		// needs THREAD_SET_LIMITED_INFORMATION
		bool SetPriority(ThreadPriorityLevel priority) noexcept;
		// the processors the thread may run on, in its processor group (a thread runs in one): its mask, and the ones it
		// can be given (its process's affinity, when the process is in that group only; else the group's active
		// processors). Needs THREAD_QUERY_LIMITED_INFORMATION; the process is opened with limited query access
		bool GetAffinity(uint16_t& group, KAFFINITY& mask, KAFFINITY& allowed) const noexcept;
		// within the thread's group; needs THREAD_SET_INFORMATION and THREAD_QUERY_INFORMATION
		bool SetAffinity(KAFFINITY mask) noexcept;
		CpuNumber GetIdealProcessor() const noexcept;
		bool Terminate(uint32_t exitCode = 0) noexcept;
		// one more (or one less) suspension; a thread runs when its count gets to 0. Need THREAD_SUSPEND_RESUME
		bool Suspend() noexcept;
		bool Resume() noexcept;
		// FILETIME units; 0 on failure. With the ID, tells the thread from a later one that reuses the ID
		[[nodiscard]] int64_t GetCreateTime() const noexcept;
		int GetMemoryPriority() const noexcept;
		IoPriority GetIoPriority() const noexcept;
		// CPU cycles the thread used (QueryThreadCycleTime); 0 on failure
		uint64_t GetCycleTime() const noexcept;
		size_t GetSubProcessTag() const noexcept;
		std::wstring GetServiceNameByTag(uint32_t pid) const noexcept;
		ComFlags GetComFlags() const noexcept;

	private:
		HANDLE m_handle{ nullptr };
		bool m_own;
	};

}


