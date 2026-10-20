#pragma once

#include <string>
#include <vector>
#include <optional>
#include <wil/resource.h>

namespace WinSys {
	struct ProcessJob {
		wil::unique_handle Handle;	// JOB_OBJECT_QUERY
		std::wstring Name;	// empty if unnamed
		bool Silo{ false };
		uint32_t ActiveProcesses{ 0 };
	};

	//
	// Jobs. No API opens the job a process is in, so FindProcessJobs scans the system handle table for Job handles,
	// duplicates them from their owners (PROCESS_DUP_HANDLE, so mostly only when elevated) and keeps the ones the process
	// is in (IsProcessInJob), told apart with NtCompareObjects. For nested jobs those are the job and its ancestors.
	//
	struct JobInfo final {
		// the process's jobs (hProcess: limited query access), innermost first: the fewest active processes, as an ancestor
		// holds its children's processes and more. Nothing documented gives a job's parent, so when two jobs have as many
		// processes their order isn't known: ordered (if given) is set false then. nullopt (with the last error) if the
		// handle table can't be read; empty if no handle to a job of the process could be duplicated
		[[nodiscard]] static std::optional<std::vector<ProcessJob>> FindProcessJobs(HANDLE hProcess, bool* ordered = nullptr);

		// the job's object name; empty if unnamed
		[[nodiscard]] static std::wstring GetName(HANDLE hJob);
		[[nodiscard]] static uint32_t GetActiveProcesses(HANDLE hJob);
		// the IDs of the job's processes; empty if they can't be read
		[[nodiscard]] static std::vector<uint32_t> GetProcessIds(HANDLE hJob);
	};
}
