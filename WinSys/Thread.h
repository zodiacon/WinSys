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
		bool Open(uint32_t tid, ThreadAccessMask accessMask = ThreadAccessMask::QueryInformation);
		~Thread();

		HANDLE Handle() const {
			return m_handle;
		}

		operator bool() const {
			return IsValid();
		}
		bool IsValid() const;

		ThreadPriorityLevel GetPriority() const;
		bool SetPriority(ThreadPriorityLevel priority);
		CpuNumber GetIdealProcessor() const;
		bool Terminate(uint32_t exitCode = 0);
		int GetMemoryPriority() const;
		IoPriority GetIoPriority() const;
		size_t GetSubProcessTag() const;
		std::wstring GetServiceNameByTag(uint32_t pid) const;
		ComFlags GetComFlags() const;

	private:
		HANDLE m_handle{ nullptr };
		bool m_own;
	};

}


