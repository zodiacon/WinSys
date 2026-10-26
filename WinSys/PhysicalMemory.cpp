#include "pch.h"
#include "PhysicalMemory.h"
#include "SecurityHelper.h"

using namespace WinSys;

namespace {
	NTSTATUS QuerySuperfetch(SUPERFETCH_INFORMATION_CLASS infoClass, void* data, ULONG size, ULONG* needed = nullptr) {
		SUPERFETCH_INFORMATION info{ SUPERFETCH_INFORMATION_VERSION, SUPERFETCH_INFORMATION_MAGIC, infoClass, data, size };
		ULONG length = 0;
		auto status = ::NtQuerySystemInformation(SystemSuperfetchInformation, &info, sizeof(info), &length);
		if (needed)
			*needed = length;
		return status;
	}

	// the ranges in a structure of the given version (V1 before Windows 10 1607 or so, V2 since)
	template<typename TInfo>
	NTSTATUS QueryRanges(ULONG version, std::vector<PhysicalMemoryRange>& ranges) {
		ULONG size = sizeof(TInfo) + 63 * sizeof(PF_PHYSICAL_MEMORY_RANGE);
		for (int attempt = 0; attempt < 4; attempt++) {
			auto buffer = std::make_unique<BYTE[]>(size);
			auto info = reinterpret_cast<TInfo*>(buffer.get());
			info->Version = version;
			ULONG needed = 0;
			auto status = QuerySuperfetch(SuperfetchMemoryRangesQuery, info, size, &needed);
			if (status == STATUS_BUFFER_TOO_SMALL) {
				size = needed > size ? needed : size * 4;
				continue;
			}
			if (!NT_SUCCESS(status))
				return status;
			ranges.reserve(info->RangeCount);
			for (ULONG i = 0; i < info->RangeCount; i++)
				ranges.push_back({ info->Ranges[i].BasePfn, info->Ranges[i].PageCount });
			return status;
		}
		return STATUS_BUFFER_TOO_SMALL;
	}

	NTSTATUS GetRanges(std::vector<PhysicalMemoryRange>& ranges) {
		SecurityHelper::EnablePrivilege(SE_PROF_SINGLE_PROCESS_NAME, true);
		auto status = QueryRanges<PF_PHYSICAL_MEMORY_RANGE_INFO_V2>(PF_PHYSICAL_MEMORY_RANGE_INFO_V2_VERSION, ranges);
		if (status == STATUS_PRIVILEGE_NOT_HELD || status == STATUS_ACCESS_DENIED || NT_SUCCESS(status))
			return status;
		ranges.clear();
		return QueryRanges<PF_PHYSICAL_MEMORY_RANGE_INFO_V1>(PF_PHYSICAL_MEMORY_RANGE_INFO_V1_VERSION, ranges);
	}
}

std::vector<PhysicalMemoryRange> PhysicalMemory::GetRanges() {
	std::vector<PhysicalMemoryRange> ranges;
	if (auto status = ::GetRanges(ranges); !NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return {};
	}
	return ranges;
}

std::optional<PageUseCounts> PageUseCounts::Read(std::atomic<bool> const* cancel) {
	std::vector<PhysicalMemoryRange> ranges;
	if (auto status = ::GetRanges(ranges); !NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return std::nullopt;
	}

	// a request for this many pages at a time: 1.5 MB on x64
	const ULONG_PTR batch = 64 * 1024;
	const ULONG size = (ULONG)(FIELD_OFFSET(PF_PFN_PRIO_REQUEST, PageData) + batch * sizeof(MMPFN_IDENTITY));
	auto buffer = std::make_unique<BYTE[]>(size);
	auto request = reinterpret_cast<PF_PFN_PRIO_REQUEST*>(buffer.get());

	SYSTEM_INFO si;
	::GetSystemInfo(&si);
	PageUseCounts counts;
	counts.PageSize = si.dwPageSize;
	for (auto& range : ranges) {
		counts.TotalPages += range.PageCount;
		for (uint64_t done = 0; done < range.PageCount; ) {
			if (cancel && cancel->load()) {
				::SetLastError(ERROR_CANCELLED);
				return std::nullopt;
			}
			auto count = (ULONG_PTR)std::min<uint64_t>(batch, range.PageCount - done);
			::memset(request, 0, FIELD_OFFSET(PF_PFN_PRIO_REQUEST, PageData));
			request->Version = PF_PFN_PRIO_REQUEST_VERSION;
			request->RequestFlags = PF_PFN_PRIO_REQUEST_QUERY_MEMORY_LIST;
			request->PfnCount = count;
			for (ULONG_PTR i = 0; i < count; i++) {
				::memset(&request->PageData[i], 0, sizeof(MMPFN_IDENTITY));
				request->PageData[i].PageFrameIndex = (ULONG_PTR)(range.BasePage + done + i);
			}
			auto status = QuerySuperfetch(SuperfetchPfnQuery, request,
				(ULONG)(FIELD_OFFSET(PF_PFN_PRIO_REQUEST, PageData) + count * sizeof(MMPFN_IDENTITY)));
			if (!NT_SUCCESS(status)) {
				::SetLastError(::RtlNtStatusToDosError(status));
				return std::nullopt;
			}
			for (ULONG_PTR i = 0; i < count; i++) {
				auto& frame = request->PageData[i].u1.e1;
				auto list = (size_t)frame.ListDescription;
				switch ((PageList)list) {
					case PageList::Zeroed: case PageList::Free: case PageList::Bad:
						// what the page held before means nothing now
						counts.Unused[list]++;
						break;
					default:
						counts.Pages[frame.UseDescription][list]++;
						break;
				}
			}
			done += count;
		}
	}
	return counts;
}
