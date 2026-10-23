#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// Zombie processes: processes that exited, whose process objects open handles keep alive (each one keeps its PID
// and kernel memory in use). They're gone from the process list, so they're found through those handles: the system
// handle table's Process handles, duplicated from their owners (PROCESS_DUP_HANDLE, so mostly only when elevated).
//

namespace WinSys {
	// a handle that keeps a zombie alive
	struct ZombieHolder {
		uint32_t Pid;		// the process holding it
		uint64_t Handle;	// its value in that process
		uint32_t Access;
		uint32_t Attributes;	// the handle table's: OBJ_PROTECT_CLOSE (1), OBJ_INHERIT (2)
	};

	struct ZombieProcess {
		uint32_t Pid;
		void* Object{ nullptr };	// the process object's address; null when not elevated
		std::wstring ImagePath;		// Win32
		int64_t CreateTime{ 0 }, ExitTime{ 0 };	// FILETIME
		uint32_t ExitCode{ 0 };
		std::vector<ZombieHolder> Holders;
	};

	struct ZombieProcesses final {
		// The zombies, by process object (its address when known, else its PID and creation time), each with the
		// handles that keep it. This process's own handles are left out (a tool's handles to processes it shows come and
		// go). Every Process handle is duplicated unless its object's address shows it was checked already, so it's a
		// few thousand calls without elevation. Nothing if the handle table can't be read, with the last error
		[[nodiscard]] static std::optional<std::vector<ZombieProcess>> Find();
	};
}
