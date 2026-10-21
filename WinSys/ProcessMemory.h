#pragma once

#include <optional>
#include <cstdint>

//
// Another process's memory: searching, reading and writing.
//

namespace WinSys {
	struct ProcessMemory final {
		// the first address in [from, to) where the pattern starts, searching the committed regions that can be read
		// without side effects (not no-access or guard pages: a read would clear a page's guard); a match can't span two
		// regions. ignoreCase: ASCII letters match either case (in UTF-16 text too, whose other bytes are zero). hProcess
		// has PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ. Nothing if it isn't there
		[[nodiscard]] static std::optional<uint64_t> Find(HANDLE hProcess, uint8_t const* pattern, size_t size, uint64_t from, uint64_t to,
			bool ignoreCase = false);
		// reads what it can: the bytes of pages that can't be read are zero. The number of bytes read
		static size_t Read(HANDLE hProcess, uint64_t address, void* buffer, size_t size);
		// hProcess has PROCESS_VM_WRITE and PROCESS_VM_OPERATION (WriteProcessMemory makes a read-only or executable page
		// writable for the write); false with the last error on failure
		static bool Write(HANDLE hProcess, uint64_t address, void const* data, size_t size);
		// the highest user-mode address
		[[nodiscard]] static uint64_t MaxAddress();
	};
}
