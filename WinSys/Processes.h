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
		explicit Process(HANDLE handle = nullptr) noexcept;
		bool Open(uint32_t pid, ProcessAccessMask access) noexcept;

		operator bool() const noexcept {
			return IsValid();
		}
		bool IsValid() const noexcept;

		std::wstring GetFullImageName() const;
		std::wstring GetCommandLine() const;
		std::wstring GetUserName() const noexcept;
		std::wstring GetName() const;
		std::wstring GetWindowTitle() const;

		ProcessProtection GetProtection() const noexcept;
		bool Terminate(uint32_t exitCode = 0) noexcept;
		bool Suspend() noexcept;
		bool Resume() noexcept;
		bool IsImmersive() const noexcept;
		bool IsProtected() const noexcept;
		bool IsSecure() const noexcept;
		bool IsInJob(HANDLE hJob = nullptr) const noexcept;
		bool IsWow64Process() const noexcept;
		bool IsManaged() const noexcept;
		bool IsElevated() const noexcept;
		bool Is64Bit() const noexcept;
		bool IsTerminated() const noexcept;
		bool IsSuspended() const noexcept;
		bool IsPico() const noexcept;
		WinSys::IntegrityLevel GetIntegrityLevel() const noexcept;
		int GetMemoryPriority() const noexcept;
		WinSys::IoPriority GetIoPriority() const noexcept;
		WinSys::ProcessPriorityClass GetPriorityClass() const noexcept;
		std::wstring GetCurrentDirectory() const noexcept;
		static std::wstring GetCurrentDirectory(HANDLE hProcess) noexcept;
		static std::vector<std::pair<std::wstring, std::wstring>> GetEnvironment(HANDLE hProcess) noexcept;
		std::vector<std::pair<std::wstring, std::wstring>> GetEnvironment() const noexcept;

		bool SetPriorityClass(ProcessPriorityClass pc) noexcept;
		uint32_t GetGdiObjectCount() const noexcept;
		uint32_t GetPeakGdiObjectCount() const noexcept;
		uint32_t GetUserObjectCount() const noexcept;
		uint32_t GetPeakUserObjectCount() const noexcept;
		VirtualizationState GetVirtualizationState() const noexcept;
		HANDLE GetNextThread(HANDLE hThread = nullptr, WinSys::ThreadAccessMask access = WinSys::ThreadAccessMask::QueryLimitedInformation);
		WinSys::DpiAwareness GetDpiAwareness() const noexcept;

		uint32_t GetId() const noexcept;
		HANDLE Handle() const noexcept;

		std::optional<WinSys::ProcessWindowInfo> GetWindowInformation() const;
		std::vector<std::shared_ptr<WinSys::ProcessHandleInfo>> EnumHandles();

	private:
		wil::unique_handle m_Handle;
	};
}
