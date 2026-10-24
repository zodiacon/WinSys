#pragma once

#include <optional>
#include <string>

//
// A Task Scheduler task that starts a program when the current user signs in, in the task folder's root, through the
// Task Scheduler's COM API (the caller initializes COM). With the highest run level the program starts elevated
// without a UAC prompt; registering or deleting such a task needs an elevated caller. Failures set the last error (a
// Win32 error, or the HRESULT when it isn't one).
//
namespace WinSys {
	struct LogonTaskAction {
		std::wstring Path, Arguments;
	};

	struct LogonTask final {
		// replaces a task by that name; no time limit, also on batteries, at normal priority (a task's default, 7,
		// would start the program below normal, with low I/O and memory priority)
		static bool Register(std::wstring const& name, std::wstring const& path, std::wstring const& arguments, bool highest,
			std::wstring const& description = {});
		static bool Delete(std::wstring const& name);
		// the task's first action; nothing if there's no such task or it can't be read
		[[nodiscard]] static std::optional<LogonTaskAction> GetAction(std::wstring const& name);
	};
}
