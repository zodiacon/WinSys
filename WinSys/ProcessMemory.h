#pragma once

#include <optional>
#include <cstdint>
#include <string>
#include <vector>

//
// Another process's memory: searching, reading and writing.
//

namespace WinSys {
	// a run of text in a process's memory (FindStrings)
	struct MemoryString {
		uint64_t Address{ 0 };
		uint32_t Length{ 0 };	// characters (a wide string's bytes are twice as many)
		bool Wide{ false };		// UTF-16
		std::wstring Text;		// at most StringScanOptions::MaxText characters of it
	};

	struct StringScanOptions {
		uint32_t MinLength{ 4 };	// characters
		bool Ascii{ true };
		bool Unicode{ true };		// UTF-16 at even addresses
		size_t MaxResults{ 200000 };
		uint32_t MaxText{ 1024 };
	};

	// told how far a scan got; returning false stops it (a non-owning interface, not std::function: see CLAUDE.md)
	struct StringScanProgress {
		virtual bool OnProgress(uint64_t scanned, uint64_t total) = 0;
	};

	struct ProcessMemory final {
		// the strings in [from, to), as Sysinternals' Strings finds them: runs of at least MinLength printable characters
		// (ASCII 0x20-0x7E and tab; a UTF-16 string's Latin-1 0xA0-0xFF too), single bytes and UTF-16 units (at even addresses), in the
		// committed regions that can be read without side effects (as Find; a run may cross adjacent readable regions).
		// In address order, the single-byte and the wide ones interleaved. truncated: MaxResults was reached (or progress
		// stopped the scan). hProcess has PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ
		[[nodiscard]] static std::vector<MemoryString> FindStrings(HANDLE hProcess, uint64_t from, uint64_t to, StringScanOptions const& options,
			StringScanProgress* progress = nullptr, bool* truncated = nullptr);

		// the first address in [from, to) where the pattern starts, searching the committed regions that can be read
		// without side effects (not no-access or guard pages: a read would clear a page's guard); a match may span
		// adjacent readable regions. ignoreCase: ASCII letters match either case; with wide, the pattern is UTF-16 and
		// only its ASCII characters (a letter byte with a zero byte after it) are folded, so U+41xx doesn't match U+61xx.
		// hProcess has PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ. Nothing if it isn't there
		[[nodiscard]] static std::optional<uint64_t> Find(HANDLE hProcess, uint8_t const* pattern, size_t size, uint64_t from, uint64_t to,
			bool ignoreCase = false, bool wide = false);
		// reads what it can: the bytes of pages that can't be read are zero. The number of bytes read
		static size_t Read(HANDLE hProcess, uint64_t address, void* buffer, size_t size);
		// hProcess has PROCESS_VM_WRITE and PROCESS_VM_OPERATION (WriteProcessMemory makes a read-only or executable page
		// writable for the write); false with the last error on failure
		static bool Write(HANDLE hProcess, uint64_t address, void const* data, size_t size);
		// the highest user-mode address
		[[nodiscard]] static uint64_t MaxAddress();
		// the NT path of the file mapped at the address (an image or a data file), whatever its length (GetMappedFileName
		// cuts it to the buffer it's given); empty if nothing is mapped there or it can't be queried. hProcess has
		// PROCESS_QUERY_INFORMATION (or limited)
		[[nodiscard]] static std::wstring GetMappedFileName(HANDLE hProcess, void const* address);
	};
}
