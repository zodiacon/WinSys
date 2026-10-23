#pragma once

#include <memory>
#include <string>
#include <optional>
#include <vector>
#include <unordered_map>
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

	// the mitigation policies that are on (see Process::GetMitigations)
	struct ProcessMitigations {
		bool Dep{ false }, DepPermanent{ false };	// always both for a 64-bit process
		bool AslrBottomUp{ false }, AslrForceRelocate{ false }, AslrHighEntropy{ false };
		bool Cfg{ false }, CfgStrict{ false };
		bool Cet{ false }, CetStrict{ false };	// user-mode shadow stacks
		bool DynamicCodeProhibited{ false };	// ACG
		bool MicrosoftSignedOnly{ false };		// CIG
		bool StrictHandleChecks{ false };
		bool Win32kDisabled{ false };			// system calls to win32k
		bool ExtensionPointsDisabled{ false };
		bool NonSystemFontsDisabled{ false };
		bool NoRemoteImages{ false }, NoLowLabelImages{ false };
		bool NoChildProcesses{ false };
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
		// the processor groups the process's threads are in (GetProcessGroupAffinity); empty on failure
		[[nodiscard]] std::vector<uint16_t> GetGroups() const noexcept;
		// the default CPU sets (Windows 11 and Server 2022 on; ERROR_NOT_SUPPORTED before): the processors, of any
		// groups, the threads without CPU sets or an affinity of their own run on. What restricts a process across
		// groups, as it has no single affinity mask then. Get: empty if none are set (PROCESS_QUERY_LIMITED_INFORMATION);
		// nothing on failure. Set: empty clears them (PROCESS_SET_LIMITED_INFORMATION)
		[[nodiscard]] std::optional<std::vector<GROUP_AFFINITY>> GetDefaultCpuSetMasks() const noexcept;
		bool SetDefaultCpuSetMasks(std::vector<GROUP_AFFINITY> const& masks) noexcept;
		// EcoQoS: execution speed throttled (Task Manager's efficiency mode also sets the idle priority class); nothing
		// if it can't be queried
		[[nodiscard]] std::optional<bool> GetEfficiencyMode() const noexcept;
		// as Task Manager does it: EcoQoS and the idle priority class; off, the system decides again, at normal priority
		bool SetEfficiencyMode(bool on) noexcept;
		// a critical process (ProcessBreakOnTermination): when it exits, however it does, the system bugchecks
		// (CRITICAL_PROCESS_DIED). Nothing if it can't be queried (limited query access)
		[[nodiscard]] std::optional<bool> IsCritical() const noexcept;
		// needs PROCESS_SET_INFORMATION and SeDebugPrivilege, which is enabled first (an elevated token has it);
		// protected processes (csrss, smss, wininit, services...) can't be opened for it
		bool SetCritical(bool critical) noexcept;
		// trims the working set to nothing (SetProcessWorkingSetSizeEx with -1, -1); the pages go to the standby and
		// modified lists, and are faulted back in as they're used. Needs PROCESS_SET_QUOTA
		bool EmptyWorkingSet() noexcept;
		// starts the process again: its image path, command line, current directory and environment are read, the process
		// is terminated (and waited for, up to 5 seconds), and a new one is created with them, as the caller
		// (CreateProcess: not as the process's user if that's another, and not as a service or a packaged app). Needs
		// PROCESS_TERMINATE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ and SYNCHRONIZE; nothing is terminated if the
		// image path can't be read. The new process's ID; nothing on failure, with the last error
		[[nodiscard]] std::optional<uint32_t> Restart();
		// starts the postmortem debugger (the Debugger value of the AeDebug key) to attach to the process: its "%ld" is
		// the process ID, and the arguments that pass a crash's event and JIT_DEBUG_INFO ("-e %ld", "-j 0x%p") are left
		// out. Nothing on failure, with the last error (ERROR_FILE_NOT_FOUND: no debugger is registered)
		[[nodiscard]] static std::optional<uint32_t> AttachDebugger(uint32_t pid);
		// the AeDebug key's Debugger command line; empty if none is registered
		[[nodiscard]] static std::wstring GetPostmortemDebugger();
		// the PEB, and each thread's TEB and stack (the 32-bit ones of a WOW64 process too). hProcess needs
		// PROCESS_QUERY_INFORMATION (the threads are opened from it), and PROCESS_VM_READ for the stacks
		[[nodiscard]] static ProcessStructures GetStructures(HANDLE hProcess);
		// the loaded modules (EnumProcessModulesEx; a WOW64 process's 32-bit ones too); hProcess needs query and VM read
		// access. Cheaper than ProcessModuleTracker, which walks the address space; no mapped data files
		[[nodiscard]] static std::vector<LoadedModule> EnumLoadedModules(HANDLE hProcess);
		// the running processes' IDs and image names, from a ToolHelp snapshot (the Idle process left out)
		[[nodiscard]] static std::vector<std::pair<uint32_t, std::wstring>> EnumProcessNames();
		// the processes with a visible top-level window that's hung (IsHungAppWindow: no messages taken for 5 seconds),
		// as Task Manager's "Not responding" (DWM's ghost windows left out); sends no message, so it doesn't wait on them.
		// Sorted
		[[nodiscard]] static std::vector<uint32_t> GetHungProcesses();

		// starts a command line as the shell does (ShellExecuteEx: a program, a document, a folder or a URL); its first
		// token is the file (quoted if it has spaces), the rest the arguments. elevated: with the runas verb (the UAC
		// prompt). The new process's ID (0 if the shell handed it to a running one); nothing on failure, with the last
		// error (ERROR_CANCELLED: the prompt was declined)
		[[nodiscard]] static std::optional<uint32_t> Run(std::wstring const& commandLine, bool elevated = false, HWND hOwner = nullptr);
		// starts a program as another user (CreateProcessWithLogonW). user: DOMAIN\user, user@domain or a local account's
		// name; loadProfile: the user's profile is loaded first; netOnly: the credentials are used only for network
		// access (as runas /netonly), and the process runs as the caller. The new process's ID; nothing on failure, with
		// the last error
		[[nodiscard]] static std::optional<uint32_t> RunAs(std::wstring const& commandLine, std::wstring const& user,
			std::wstring const& password, bool loadProfile = true, bool netOnly = false);
		// starts a program as the caller without administrator rights: a Safer "normal user" token made from the caller's
		// (the Administrators group deny-only, most privileges removed), at medium integrity if the caller's is higher
		// (CreateProcessAsUser, which takes a token filtered from the caller's own without a privilege). The command line's
		// first token is the program (CreateProcess's rules: an executable, not a document). The new process's ID;
		// nothing on failure, with the last error
		[[nodiscard]] static std::optional<uint32_t> RunLimited(std::wstring const& commandLine);
		// the most handles the process has had at once (ProcessHandleCount); nothing if it can't be queried (limited
		// query access)
		[[nodiscard]] std::optional<uint32_t> GetPeakHandleCount() const noexcept;
		uint32_t GetGdiObjectCount() const noexcept;
		uint32_t GetPeakGdiObjectCount() const noexcept;
		uint32_t GetUserObjectCount() const noexcept;
		uint32_t GetPeakUserObjectCount() const noexcept;
		VirtualizationState GetVirtualizationState() const noexcept;
		HANDLE GetNextThread(HANDLE hThread = nullptr, WinSys::ThreadAccessMask access = WinSys::ThreadAccessMask::QueryLimitedInformation);
		// from the process's DPI awareness context (Unknown if it can't be queried; limited query access)
		WinSys::DpiAwareness GetDpiAwareness() const noexcept;
		// the package's full name of a packaged app's process (GetPackageFullName); empty for an unpackaged one or on
		// failure. Limited query access
		[[nodiscard]] std::wstring GetPackageFullName() const;
		// GetProcessMitigationPolicy for each policy; nothing if none could be queried. Most need
		// PROCESS_QUERY_INFORMATION; some work with limited access
		[[nodiscard]] std::optional<ProcessMitigations> GetMitigations() const noexcept;
		// each process's main window's title, as InternalGetWindowText has it (no message sent): its first visible,
		// unowned top-level window with a title, not a tool window, in Z order. One pass over the top-level windows
		[[nodiscard]] static std::unordered_map<uint32_t, std::wstring> GetMainWindowTitles();

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
