#include "pch.h"
#include "Heaps.h"
#include <wil/resource.h>

namespace WinSys {
	namespace {
		// the first field of both layouts; the V2 entries are 8 bytes longer (the heap tag at the end)
		static_assert(sizeof(RTL_HEAP_INFORMATION_V1) == 88 && sizeof(RTL_HEAP_INFORMATION_V2) == 96);

		// the heap's signature, 16 bytes in (64-bit): _HEAP's SegmentSignature or _SEGMENT_HEAP's Signature
		const ULONG SignatureOffset = 0x10;

		template<typename T>
		std::vector<HeapInfo> ParseAs(void const* processHeaps) {
			struct Heaps {
				ULONG NumberOfHeaps;
				T Heaps[1];
			};
			auto heaps = static_cast<Heaps const*>(processHeaps);
			std::vector<HeapInfo> result;
			result.reserve(heaps->NumberOfHeaps);
			for (ULONG i = 0; i < heaps->NumberOfHeaps; i++) {
				auto& h = heaps->Heaps[i];
				HeapInfo info;
				info.Address = (uint64_t)h.BaseAddress;
				info.Flags = h.Flags;
				info.EntryOverhead = h.EntryOverhead;
				info.Kind = h.EntryOverhead == 0 ? HeapKind::Segment : HeapKind::Nt;
				info.Committed = h.BytesCommitted;
				info.Allocated = h.BytesAllocated;
				// with RTL_QUERY_PROCESS_HEAP_SEGMENTS the entries are the segments
				for (ULONG e = 0; h.Entries && e < h.NumberOfEntries; e++) {
					auto& entry = h.Entries[e];
					if (entry.Flags & RTL_HEAP_SEGMENT) {
						info.Segments++;
						info.Reserved += entry.Size;
					}
				}
				result.push_back(info);
			}
			return result;
		}

		// the process heap's address from the PEB; 0 if it can't be read
		uint64_t GetDefaultHeap(HANDLE hProcess) {
			PROCESS_BASIC_INFORMATION info;
			if (!NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &info, sizeof(info), nullptr)) || !info.PebBaseAddress)
				return 0;
			PVOID heap = nullptr;
			if (!::ReadProcessMemory(hProcess, (BYTE*)info.PebBaseAddress + offsetof(PEB, ProcessHeap), &heap, sizeof(heap), nullptr))
				return 0;
			return (uint64_t)heap;
		}
	}

	bool ProcessHeaps::UsesV2() {
		static const bool v2 = [] {
			RTL_OSVERSIONINFOEXW version{ sizeof(version) };
			return NT_SUCCESS(::RtlGetVersion(&version)) && version.dwBuildNumber > 22000;
		}();
		return v2;
	}

	std::vector<HeapInfo> ProcessHeaps::Parse(void const* processHeaps, bool v2) {
		if (!processHeaps)
			return {};
		return v2 ? ParseAs<RTL_HEAP_INFORMATION_V2>(processHeaps) : ParseAs<RTL_HEAP_INFORMATION_V1>(processHeaps);
	}

	std::optional<std::vector<HeapInfo>> ProcessHeaps::Query(uint32_t pid) {
		const ULONG flags = RTL_QUERY_PROCESS_HEAP_SUMMARY | RTL_QUERY_PROCESS_HEAP_SEGMENTS | RTL_QUERY_PROCESS_NONINVASIVE;
		// the default buffer, then a larger one for a process with very many heaps or segments
		NTSTATUS status = STATUS_NO_MEMORY;
		std::vector<HeapInfo> heaps;
		for (ULONG maxCommit : { 0UL, 64UL << 20 }) {
			auto buffer = ::RtlCreateQueryDebugBuffer(maxCommit, FALSE);
			if (!buffer)
				break;
			status = ::RtlQueryProcessDebugInformation(ULongToHandle(pid), flags, buffer);
			if (NT_SUCCESS(status))
				heaps = Parse(buffer->Heaps, UsesV2());
			::RtlDestroyQueryDebugBuffer(buffer);
			if (status != STATUS_NO_MEMORY)
				break;
		}
		if (!NT_SUCCESS(status)) {
			::SetLastError(::RtlNtStatusToDosError(status));
			return {};
		}

		// the default heap, and the kind from each heap's signature where the memory can be read (else the guess from
		// the entry overhead stays)
		wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
		if (hProcess) {
			auto defaultHeap = GetDefaultHeap(hProcess.get());
			for (auto& heap : heaps) {
				heap.Default = heap.Address == defaultHeap;
				ULONG signature = 0;
				if (::ReadProcessMemory(hProcess.get(), (BYTE*)heap.Address + SignatureOffset, &signature, sizeof(signature), nullptr)) {
					if (signature == RTL_HEAP_SIGNATURE)
						heap.Kind = HeapKind::Nt;
					else if (signature == RTL_HEAP_SEGMENT_SIGNATURE)
						heap.Kind = HeapKind::Segment;
				}
			}
		}
		return heaps;
	}

	std::wstring ProcessHeaps::ClassText(uint32_t flags) {
		switch (flags & HEAP_CLASS_MASK) {
			case HEAP_CLASS_1: return L"Private";
			case HEAP_CLASS_2: return L"Kernel";
			case HEAP_CLASS_3: return L"GDI";
			case HEAP_CLASS_4: return L"User";
			case HEAP_CLASS_5: return L"Console";
			case HEAP_CLASS_6: return L"User desktop";
			case HEAP_CLASS_7: return L"CSR shared";
			case HEAP_CLASS_8: return L"CSR port";
			case HEAP_CLASS_0: return L"";
		}
		return L"Class " + std::to_wstring((flags & HEAP_CLASS_MASK) >> 12);
	}

	std::wstring ProcessHeaps::FlagsText(uint32_t flags) {
		static const struct {
			uint32_t Flag;
			PCWSTR Text;
		} names[] = {
			{ HEAP_GROWABLE, L"Growable" },
			{ HEAP_NO_SERIALIZE, L"No serialize" },
			{ HEAP_GENERATE_EXCEPTIONS, L"Exceptions" },
			{ HEAP_ZERO_MEMORY, L"Zero memory" },
			{ HEAP_TAIL_CHECKING_ENABLED, L"Tail checking" },
			{ HEAP_FREE_CHECKING_ENABLED, L"Free checking" },
			{ HEAP_DISABLE_COALESCE_ON_FREE, L"No coalescing" },
			{ HEAP_CREATE_ALIGN_16, L"Align 16" },
			{ HEAP_CREATE_ENABLE_TRACING, L"Tracing" },
			{ HEAP_CREATE_ENABLE_EXECUTE, L"Executable" },
		};
		std::wstring text;
		for (auto& name : names) {
			if (flags & name.Flag) {
				if (!text.empty())
					text += L", ";
				text += name.Text;
			}
		}
		return text;
	}
}
