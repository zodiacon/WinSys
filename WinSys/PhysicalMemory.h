#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <optional>
#include <vector>

//
// Physical memory page by page, as RAMMap's Use Counts: every page's use (process private, mapped file, paged pool...)
// and list (active, standby, modified, free...) from the memory manager's PFN database, through the Superfetch
// information class (SuperfetchMemoryRangesQuery for the RAM's ranges, then SuperfetchPfnQuery for their pages in
// batches). Both need SeProfileSingleProcessPrivilege, which Read enables: so administrator rights.
//
namespace WinSys {
	// MMPFNLIST_*: the list a page is on (Active: in use, mapped by some page table)
	enum class PageList : uint8_t {
		Zeroed, Free, Standby, Modified, ModifiedNoWrite, Bad, Active, Transition,
		_Count
	};

	// MMPFNUSE_*: what an in-use (or standby, modified...) page holds; 4 bits, so up to 16 values
	enum class PageUse : uint8_t {
		ProcessPrivate, MappedFile, Shareable /* page-file-backed sections */, PageTable, PagedPool, NonPagedPool,
		SystemPte, SessionPrivate, Metafile, Awe, DriverLocked, KernelStack,
		Hyperspace /* a process's hyperspace (working set list...): unnamed in phnt; MiIdentifyUserPage sets it for an address
			in the hyperspace range, or a page table mapping it (MiHyperPage), on Windows 11 build 29695 */,
		_Known,
		_Count = 16
	};

	struct PhysicalMemoryRange {
		uint64_t BasePage;	// page frame number
		uint64_t PageCount;
	};

	struct PageUseCounts {
		// pages by use and list: a page on the zeroed, free or bad list has no use, and is counted under Unused instead
		std::array<std::array<uint64_t, (size_t)PageList::_Count>, (size_t)PageUse::_Count> Pages{};
		std::array<uint64_t, (size_t)PageList::_Count> Unused{};	// only Zeroed, Free and Bad are set
		uint64_t TotalPages{ 0 };	// in the ranges
		uint64_t PageSize{ 0 };

		// the PFN database read: nothing (with the last error set) on failure, ERROR_ACCESS_DENIED when not elevated,
		// ERROR_CANCELLED when cancel was set (checked between batches)
		[[nodiscard]] static std::optional<PageUseCounts> Read(std::atomic<bool> const* cancel = nullptr);
	};

	struct PhysicalMemory final {
		// the RAM's ranges, as the memory manager sees them; empty (with the last error set) on failure
		[[nodiscard]] static std::vector<PhysicalMemoryRange> GetRanges();
	};
}
