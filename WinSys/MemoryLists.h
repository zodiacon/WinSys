#pragma once

#include <array>
#include <cstdint>
#include <optional>

//
// The physical memory lists in detail (SystemMemoryListInformation), as RAMMap's Priority Summary has them, and the
// commands that empty them (NtSetSystemInformation with a SYSTEM_MEMORY_LIST_COMMAND), as RAMMap's Empty menu. Both
// need SeProfileSingleProcessPrivilege, which Execute enables: so administrator rights.
//
namespace WinSys {
	enum class MemoryListCommand {
		EmptyWorkingSets = 2,			// every process's working set trimmed: its pages go to the standby and modified lists
		FlushModifiedList = 3,			// the modified pages written out: they become standby
		PurgeStandbyList = 4,			// the standby pages (the file cache, among others) freed
		PurgeLowPriorityStandbyList = 5,	// the standby pages of priority 0 freed
	};

	// sizes in bytes, but for RepurposedByPriority
	struct MemoryLists {
		uint64_t Zeroed{ 0 }, Free{ 0 };
		uint64_t Modified{ 0 };				// all of it
		uint64_t ModifiedNoWrite{ 0 };		// modified, but not to be written (yet)
		uint64_t ModifiedPageFile{ 0 };		// the part backed by a page file
		uint64_t Bad{ 0 };
		std::array<uint64_t, 8> StandbyByPriority{};
		// how many pages were taken from the standby list of each priority to be used for something else, since boot: a high
		// count at a priority means its cached data didn't stay
		std::array<uint64_t, 8> RepurposedByPriority{};

		[[nodiscard]] uint64_t Standby() const;

		// nothing (with the last error set) if the lists can't be read
		[[nodiscard]] static std::optional<MemoryLists> Read();
		// false (with the last error set) on failure: ERROR_PRIVILEGE_NOT_HELD when not elevated
		static bool Execute(MemoryListCommand command);
	};
}
