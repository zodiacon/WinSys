#pragma once

#include <memory>
#include <string>
#include <optional>
#include <vector>
#include "Enums.h"
#include <wil\resource.h>

namespace WinSys {
	struct ProcessHandleInfo;

	struct ProcessProtection {
		union {
			uint8_t Level;
			struct {
				uint8_t Type : 3;
				uint8_t Audit : 1;
				ProcessProtectionSigner Signer: 4;
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

		ProcessProtection GetProtection() const;
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
		bool Is64Bit() const;
		bool IsTerminated() const;
		bool IsSuspended() const;
		bool IsPico() const;
		WinSys::IntegrityLevel GetIntegrityLevel() const;
		int GetMemoryPriority() const;
		WinSys::IoPriority GetIoPriority() const;
		WinSys::ProcessPriorityClass GetPriorityClass() const;
		std::wstring GetCurrentDirectory() const;
		static std::wstring GetCurrentDirectory(HANDLE hProcess);
		static std::vector<std::pair<std::wstring, std::wstring>> GetEnvironment(HANDLE hProcess);
		std::vector<std::pair<std::wstring, std::wstring>> GetEnvironment() const;

		bool SetPriorityClass(ProcessPriorityClass pc);
		uint32_t GetGdiObjectCount() const;
		uint32_t GetPeakGdiObjectCount() const;
		uint32_t GetUserObjectCount() const;
		uint32_t GetPeakUserObjectCount() const;
		VirtualizationState GetVirtualizationState() const;
		HANDLE GetNextThread(HANDLE hThread = nullptr, WinSys::ThreadAccessMask access = WinSys::ThreadAccessMask::QueryLimitedInformation);
		WinSys::DpiAwareness GetDpiAwareness() const;

		uint32_t GetId() const;
		HANDLE Handle() const;

		std::optional<WinSys::ProcessWindowInfo> GetWindowInformation() const;
		std::vector<std::shared_ptr<WinSys::ProcessHandleInfo>> EnumHandles();

	private:
		wil::unique_handle m_handle;
	};

}
