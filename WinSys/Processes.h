#pragma once

#include <memory>
#include <string>
#include <optional>
#include <vector>
#include "Enums.h"
#include <wil\resource.h>

#ifdef WINSYS_NAMESPACE
namespace WinSys {
#endif

	enum class ProtectedProcessSigner : uint8_t;
	struct ProcessHandleInfo;

	enum class ProcessMitigationPolicy {
		DEPPolicy,
		ASLRPolicy,
		DynamicCodePolicy,
		StrictHandleCheckPolicy,
		SystemCallDisablePolicy,
		MitigationOptionsMask,
		ExtensionPointDisablePolicy,
		ControlFlowGuardPolicy,
		SignaturePolicy,
		FontDisablePolicy,
		ImageLoadPolicy,
		SystemCallFilterPolicy,
		PayloadRestrictionPolicy,
		ChildProcessPolicy,
		SideChannelIsolationPolicy,
	};

	enum class DpiAwareness {
		Unknown = -1,
		None = DPI_AWARENESS_UNAWARE,
		System = DPI_AWARENESS_SYSTEM_AWARE,
		PerMonitor = DPI_AWARENESS_PER_MONITOR_AWARE,
	};

	struct ProcessProtection {
		union {
			uint8_t Level;
			struct {
				uint8_t Type : 3;
				uint8_t Audit : 1;
				ProtectedProcessSigner : 4;
			};
		};
	};

	struct ProcessWindowInfo {
		uint32_t Flags;
		std::wstring Title;
	};

	class Process final {
	public:
		static std::unique_ptr<Process> OpenById(uint32_t pid, ProcessAccessMask access = ProcessAccessMask::QueryLimitedInformation);
		static std::unique_ptr<Process> GetCurrent();
		explicit Process(HANDLE handle = nullptr);
		bool Open(uint32_t pid, ProcessAccessMask access);

		operator bool() const {
			return IsValid();
		}
		bool IsValid() const;

		std::wstring GetFullImageName() const;
		std::wstring GetCommandLine() const;
		std::wstring GetUserName() const;
		std::wstring GetName() const;
		std::wstring GetWindowTitle() const;

		std::optional<ProcessProtection> GetProtection() const;
		bool Terminate(uint32_t exitCode = 0);
		bool Suspend();
		bool Resume();
		bool IsImmersive() const noexcept;
		bool IsProtected() const;
		bool IsSecure() const;
		bool IsInJob(HANDLE hJob = nullptr) const;
		bool IsWow64Process() const;
		bool IsManaged() const;
		bool IsElevated() const;
		IntegrityLevel GetIntegrityLevel() const;
		int GetMemoryPriority() const;
		IoPriorityHint GetIoPriority() const;
		PriorityClass GetPriorityClass() const;
		std::wstring GetCurrentDirectory() const;
		static std::wstring GetCurrentDirectory(HANDLE hProcess);
		static std::vector<std::pair<std::wstring, std::wstring>> GetEnvironment(HANDLE hProcess);
		std::vector<std::pair<std::wstring, std::wstring>> GetEnvironment() const;

		bool SetPriorityClass(PriorityClass pc);
		uint32_t GetGdiObjectCount() const;
		uint32_t GetPeakGdiObjectCount() const;
		uint32_t GetUserObjectCount() const;
		uint32_t GetPeakUserObjectCount() const;
		HANDLE GetNextThread(HANDLE hThread = nullptr, ThreadAccessMask access = ThreadAccessMask::QueryLimitedInformation);
		DpiAwareness GetDpiAwareness() const;

		uint32_t GetId() const;
		HANDLE Handle() const;

		std::optional<ProcessWindowInfo> GetWindowInformation() const;
		std::vector<std::shared_ptr<ProcessHandleInfo>> EnumHandles();

	private:
		wil::unique_handle m_handle;
	};

#ifdef WINSYS_NAMESPACE
}
#endif
