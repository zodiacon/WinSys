#pragma once

#include <cstdint>
#include <optional>
#include <string>

//
// Signs that a process isn't what its image file says it is (process hollowing and its relatives), and the executable
// memory that no image backs. Each query reads the process once; the caller decides how often to ask. No elevation is
// needed for the caller's own processes; others' need it (PROCESS_VM_READ).
//
namespace WinSys {
	class PEFile;

	enum class ImageIntegrityStatus {
		Unknown,		// couldn't be checked: the process can't be read, or has no image (System, Registry, minimal processes)
		Ok,				// the image the PEB names is the process's file, mapped as an image, and its headers are the file's
		FileGone,		// the file can't be opened anymore (deleted, or a transaction's; legitimately, an updated program)
		ImagePrivate,	// the PEB's image base isn't an image mapping: private (or mapped data) memory took its place
		DifferentFile,	// an image is mapped there, but another file's than the process's
		HeadersDiffer,	// the headers in memory aren't the file's (rewritten in memory, or the file changed after the start)
	};

	struct ImageIntegrity {
		ImageIntegrityStatus Status{ ImageIntegrityStatus::Unknown };
		std::wstring Detail;	// what differs ("entry point 0x1A40 in memory, 0x2210 in the file"), or why it's unknown
		uint64_t ImageBase{ 0 };	// the PEB's
	};

	// committed executable memory that isn't an image's
	struct ExecutableMemory {
		uint32_t PrivateRegions{ 0 };	// MEM_PRIVATE with an execute protection (JIT compilers make these legitimately)
		uint64_t PrivateBytes{ 0 };
		uint32_t WritableRegions{ 0 };	// of those, also writable (PAGE_EXECUTE_READWRITE or _WRITECOPY)
		uint32_t MappedRegions{ 0 };	// MEM_MAPPED (a data file's or a pagefile section's view) with an execute protection
		uint64_t MappedBytes{ 0 };
	};

	struct ProcessIntegrity final {
		// the main image: the PEB's ImageBaseAddress against the mapping there and the process's image file (its first
		// page, read through \\?\GLOBALROOT from the NT path, so a volume without a letter works). hProcess has
		// PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ
		[[nodiscard]] static ImageIntegrity CheckImage(HANDLE hProcess);
		// the regions as they are now (a JIT adds more as it runs); hProcess has PROCESS_QUERY_INFORMATION (VirtualQueryEx).
		// Nothing if the walk can't start
		[[nodiscard]] static std::optional<ExecutableMemory> GetExecutableMemory(HANDLE hProcess);
		// what differs between the headers as mapped and as in the file; empty if nothing does. Not the image base,
		// which the loader rewrites when it relocates, nor the checksum. Apart, for the tests
		[[nodiscard]] static std::wstring CompareHeaders(PEFile const& memory, PEFile const& file);
		[[nodiscard]] static PCWSTR StatusText(ImageIntegrityStatus status);
	};
}
