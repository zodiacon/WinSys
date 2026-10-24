#include "pch.h"
#include "MemoryLists.h"
#include "SecurityHelper.h"

using namespace WinSys;

namespace {
	uint64_t PageSize() {
		static const uint64_t size = [] {
			SYSTEM_INFO si;
			::GetSystemInfo(&si);
			return (uint64_t)si.dwPageSize;
		}();
		return size;
	}
}

uint64_t MemoryLists::Standby() const {
	uint64_t total = 0;
	for (auto size : StandbyByPriority)
		total += size;
	return total;
}

std::optional<MemoryLists> MemoryLists::Read() {
	SecurityHelper::EnablePrivilege(SE_PROF_SINGLE_PROCESS_NAME, true);
	SYSTEM_MEMORY_LIST_INFORMATION info;
	auto status = ::NtQuerySystemInformation(SystemMemoryListInformation, &info, sizeof(info), nullptr);
	if (!NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return std::nullopt;
	}
	auto page = PageSize();
	MemoryLists lists;
	lists.Zeroed = info.ZeroPageCount * page;
	lists.Free = info.FreePageCount * page;
	lists.Modified = info.ModifiedPageCount * page;
	lists.ModifiedNoWrite = info.ModifiedNoWritePageCount * page;
	lists.ModifiedPageFile = info.ModifiedPageCountPageFile * page;
	lists.Bad = info.BadPageCount * page;
	for (int i = 0; i < 8; i++) {
		lists.StandbyByPriority[i] = info.PageCountByPriority[i] * page;
		// a count of pages, not their size: each repurposed page was used once for something else
		lists.RepurposedByPriority[i] = info.RepurposedPagesByPriority[i];
	}
	return lists;
}

bool MemoryLists::Execute(MemoryListCommand command) {
	SecurityHelper::EnablePrivilege(SE_PROF_SINGLE_PROCESS_NAME, true);
	auto value = (SYSTEM_MEMORY_LIST_COMMAND)command;
	auto status = ::NtSetSystemInformation(SystemMemoryListInformation, &value, sizeof(value));
	if (!NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}
