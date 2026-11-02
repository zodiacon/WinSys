#pragma once

#include <vector>
#include <optional>
#include <string>

namespace WinSys {
	enum class HeapKind {
		Nt,			// the NT heap (RtlCreateHeap's classic one, with the low-fragmentation heap in front)
		Segment,	// the segment heap (Windows 10 and later: UWP apps, system processes, opted-in programs)
	};

	struct HeapInfo {
		uint64_t Address{ 0 };		// the heap's handle, its base address in the process
		uint32_t Flags{ 0 };		// HEAP_* flags with the class (HEAP_CLASS_MASK); 0 for a segment heap
		HeapKind Kind{ HeapKind::Nt };
		bool Default{ false };		// the process heap (PEB.ProcessHeap, GetProcessHeap)
		uint16_t EntryOverhead{ 0 };	// bytes per block; 0 for a segment heap
		uint64_t Committed{ 0 };
		uint64_t Reserved{ 0 };		// its segments' sizes (blocks too large for a segment, allocated apart, not counted)
		uint64_t Allocated{ 0 };	// in busy blocks; not reported for a segment heap (0)
		uint32_t Segments{ 0 };
	};

	//
	// A process's heaps, from RtlQueryProcessDebugInformation's heap summary and segments, non-invasive (read from
	// outside, without a thread created in the process; about a millisecond). The caller's own processes can be read
	// without elevation, other users' (services) only elevated, protected processes not at all (ERROR_ACCESS_DENIED);
	// a 32-bit process on 64-bit Windows is refused (ERROR_INVALID_PARAMETER): the non-invasive query reads 64-bit heaps
	// only. The kinds and the default heap are read from the process's memory where it can be opened for that.
	//
	struct ProcessHeaps final {
		// nothing on failure, with the last error
		[[nodiscard]] static std::optional<std::vector<HeapInfo>> Query(uint32_t pid);

		// the heaps in an RTL_PROCESS_HEAPS buffer (its entries' pointers valid in this process), in its order:
		// RTL_HEAP_INFORMATION_V2 (with a heap tag at its end) since Windows 11 build 22000, V1 before (UsesV2). Kind and
		// Default aren't in the buffer: Kind is guessed from the entry overhead (0 only for a segment heap), Default false
		[[nodiscard]] static std::vector<HeapInfo> Parse(void const* processHeaps, bool v2);
		[[nodiscard]] static bool UsesV2();

		// the class in the flags in words ("Private", "CSR port"...); empty for the process class (0), which the
		// default heap and segment heaps (whose flags aren't reported) have
		[[nodiscard]] static std::wstring ClassText(uint32_t flags);
		// the creation flags in words, comma separated ("Growable, No serialize"); the class and settable bits left out
		[[nodiscard]] static std::wstring FlagsText(uint32_t flags);
	};
}
