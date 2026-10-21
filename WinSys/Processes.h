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

	// the system structures of a process's threads (see Process::GetStructures)
	struct ThreadStructures {
		uint32_t ThreadId;
		uint64_t Teb{ 0 }, Teb32{ 0 };	// the 32-bit TEB of a WOW64 thread
		// from the TEBs (NT_TIB): the stacks' tops and the limits of their committed parts; 0 if they couldn't be read
		uint64_t StackBase{ 0 }, StackLimit{ 0 }, Stack32Base{ 0 }, Stack32Limit{ 0 };
	};

	struct LoadedModule {
		uint64_t Base;
		std::wstring Path;
	};

	struct ProcessStructures {
		uint64_t Peb{ 0 }, Peb32{ 0 };	// the 32-bit PEB of a WOW64 process
		std::vector<ThreadStructures> Threads;	// in thread ID order
	};

	struct ProcessWindowInfo {
		uint32_t Flags;
		std::wstring Title;
	};

	class Process final {
	public:
		static std::unique_ptr<Process> OpenById(uint32_t pid, ProcessAccessMask access = ProcessAccessMask::QueryLimitedInformation);
		// only the process created at createTime (a FILETIME, as a snapshot's CreateTime), not another one that got its ID
		// since (ERROR_NOT_FOUND then); QueryLimitedInformation is added to the access to check it
		static std::unique_ptr<Process> OpenById(uint32_t pid, int64_t createTime, ProcessAccessMask access);
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
		// High needs SeIncreaseBasePriorityPrivilege, which is enabled first (an elevated token has it, disabled).
		// Needs PROCESS_SET_INFORMATION, as the setters below
		bool SetIoPriority(IoPriority priority) noexcept;
		// MEMORY_PRIORITY_VERY_LOW (1) to MEMORY_PRIORITY_NORMAL (5)
		bool SetMemoryPriority(int priority) noexcept;
		// false (and a 0 mask) for a process whose threads span processor groups: it has no single mask
		bool GetAffinity(DWORD_PTR& mask, DWORD_PTR& systemMask) const noexcept;
		bool SetAffinity(DWORD_PTR mask) noexcept;
		// EcoQoS: execution speed throttled (Task Manager's efficiency mode also sets the idle priority class); nothing
		// if it can't be queried
		[[nodiscard]] std::optional<bool> GetEfficiencyMode() const noexcept;
		// as Task Manager does it: EcoQoS and the idle priority class; off, the system decides again, at normal priority
		bool SetEfficiencyMode(bool on) noexcept;
		// the PEB, and each thread's TEB and stack (the 32-bit ones of a WOW64 process too). hProcess needs
		// PROCESS_QUERY_INFORMATION (the threads are opened from it), and PROCESS_VM_READ for the stacks
		[[nodiscard]] static ProcessStructures GetStructures(HANDLE hProcess);
		// the loaded modules (EnumProcessModulesEx; a WOW64 process's 32-bit ones too); hProcess needs query and VM read
		// access. Cheaper than ProcessModuleTracker, which walks the address space; no mapped data files
		[[nodiscard]] static std::vector<LoadedModule> EnumLoadedModules(HANDLE hProcess);
		// the running processes' IDs and image names, from a ToolHelp snapshot (the Idle process left out)
		[[nodiscard]] static std::vector<std::pair<uint32_t, std::wstring>> EnumProcessNames();
		uint32_t GetGdiObjectCount() const noexcept;
		uint32_t GetPeakGdiObjectCount() const noexcept;
		uint32_t GetUserObjectCount() const noexcept;
		uint32_t GetPeakUserObjectCount() const noexcept;
		VirtualizationState GetVirtualizationState() const noexcept;
		HANDLE GetNextThread(HANDLE hThread = nullptr, WinSys::ThreadAccessMask access = WinSys::ThreadAccessMask::QueryLimitedInformation);
		WinSys::DpiAwareness GetDpiAwareness() const noexcept;

		uint32_t GetId() const noexcept;
		// a FILETIME; 0 if it can't be queried
		[[nodiscard]] int64_t GetCreateTime() const noexcept;
		HANDLE Handle() const noexcept;

		std::optional<WinSys::ProcessWindowInfo> GetWindowInformation() const;
		std::vector<std::shared_ptr<WinSys::ProcessHandleInfo>> EnumHandles();

	private:
		wil::unique_handle m_Handle;
	};
}
