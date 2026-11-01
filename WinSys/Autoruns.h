#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// What starts by itself, as Sysinternals' Autoruns lists it (a subset of its locations):
// - Logon: the Run and RunOnce keys (HKLM, HKCU, WOW6432Node, the Explorer policies' Run), the startup folders (the
//   user's and all users'; shortcuts resolved to their targets) and Active Setup's StubPath commands.
// - Scheduled tasks: every task in every folder (hidden ones too) through the Task Scheduler's COM API, with its
//   actions, triggers, account, state and last and next runs. The caller initializes COM.
// - Services and drivers that start at boot, system start or automatically (the Services key read directly: Start
//   0-2; a svchost service's ServiceDll as its image).
// - Winlogon (Userinit, Shell, HKLM and HKCU), AppInit_DLLs (when set), Session Manager's BootExecute, the LSA's
//   authentication, notification and security packages, and image hijacks: Image File Execution Options' Debugger
//   values and SilentProcessExit's MonitorProcess.
// Each entry has its command as stored and the image it runs, resolved: quotes, environment variables, unquoted
// paths with spaces (tried word by word), the search path, rundll32's DLL, a COM handler's InprocServer32, \SystemRoot\.
// Run keys and startup items are enabled and disabled as Task Manager's Startup apps page does it (the StartupApproved
// keys); tasks through the Task Scheduler. Writing HKLM, all users' folder, and most tasks needs elevation.
//

namespace WinSys {
	enum class AutorunCategory {
		Logon,
		ScheduledTask,
		Service,
		Driver,
		Winlogon,
		AppInit,
		BootExecute,
		Lsa,
		ImageHijack,
	};

	// where it's stored, which says how it's enabled, disabled and deleted
	enum class AutorunStore {
		RegistryValue,		// a value of RegistryKey (a list's item for BootExecute and the LSA packages)
		StartupFile,		// a file in a startup folder
		Task,
		Service,			// the Services key's subkey
	};

	enum class AutorunTaskState {
		Unknown,
		Disabled,
		Queued,
		Ready,
		Running,
	};

	struct AutorunEntry {
		AutorunCategory Category{ AutorunCategory::Logon };
		AutorunStore Store{ AutorunStore::RegistryValue };
		std::wstring Location;		// the key ("HKLM\..."), the folder, the task's folder ("\Microsoft\Windows\..."), the service's key
		std::wstring Name;			// the value's name (or the list item), the file's, the task's, the service's
		std::wstring Command;		// as stored: a command line, the task's actions, the service's image path
		std::wstring ImagePath;		// the file it runs, resolved; empty if it couldn't be
		bool ImageFound{ false };	// ImagePath exists
		std::wstring Details;		// a service's display name, a task's description, a shortcut's arguments...
		std::optional<bool> Enabled;	// for those that can be disabled (StartupApproved, tasks); empty: always on
		bool Deletable{ false };	// a Run value, a startup file, a task, a hijack value: removing it removes the autorun
		int64_t LastModified{ 0 };	// FILETIME: the key's last write, the file's modification; 0 if unknown
		// the registry entries' key, as RegOpenKeyEx takes it
		void* Root{ nullptr };		// HKEY
		std::wstring SubKey;
		std::wstring ValueName;		// for the StartupApproved key too
		bool Wow64{ false };		// a Run key under WOW6432Node (its StartupApproved key is Run32)
		// tasks
		std::wstring TaskPath;		// "\Folder\Name"
		AutorunTaskState TaskState{ AutorunTaskState::Unknown };
		std::wstring Triggers;		// "At log on, Daily (2)"
		std::wstring RunAs;
		int64_t LastRun{ 0 }, NextRun{ 0 };	// FILETIME (UTC); 0: never, or none
		std::optional<int32_t> LastResult;	// HRESULT or exit code
		std::wstring Author;
	};

	struct Autoruns final {
		// every location; the caller initializes COM (for the tasks and shortcuts)
		[[nodiscard]] static std::vector<AutorunEntry> Enum();
		// for an entry with Enabled set: StartupApproved, or the task's Enabled; sets the last error on failure
		static bool SetEnabled(AutorunEntry const& entry, bool enable);
		// for a Deletable entry: the value, the file, the task; sets the last error on failure
		static bool Delete(AutorunEntry const& entry);
		// the file a command line runs (see above), or empty
		[[nodiscard]] static std::wstring ResolveImage(std::wstring const& command);
		// "HKLM", "HKCU"...
		[[nodiscard]] static PCWSTR RootName(void* root);
		[[nodiscard]] static PCWSTR CategoryName(AutorunCategory category);
		[[nodiscard]] static PCWSTR TaskStateName(AutorunTaskState state);
	};
}
