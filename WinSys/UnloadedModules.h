#pragma once

#include <vector>
#include <optional>
#include <string>

namespace WinSys {
	struct UnloadedModule {
		uint64_t BaseAddress{ 0 };
		uint64_t Size{ 0 };
		uint32_t Sequence{ 0 };		// the unload's number in the process: higher is later
		uint32_t TimeDateStamp{ 0 };	// the image's link time stamp (seconds since 1970), not the unload's time
		uint32_t CheckSum{ 0 };
		uint64_t Version{ 0 };		// the image's product version (not its file version), 16 bits a part, major highest; 0 if none
		std::wstring Name;		// the file name only, as the loader keeps it (at most 31 characters)
	};

	//
	// The modules a process unloaded lately: ntdll's unload event trace, a ring of RTL_UNLOAD_EVENT_TRACE_NUMBER (64)
	// RTL_UNLOAD_EVENT_TRACE entries the loader fills as DLLs unload. RtlGetUnloadEventTraceEx gives the addresses of
	// its element size, count and array pointer in this process's ntdll, which is at the same address in every process,
	// so they're read from the target (PROCESS_VM_READ). For a 32-bit process on 64-bit Windows this is the 64-bit
	// ntdll's trace (the WOW64 layer's own DLLs); its 32-bit DLLs are in the 32-bit ntdll's, which isn't read.
	//
	struct UnloadedModules final {
		// newest first; empty if nothing was unloaded yet; nothing on failure, with the last error set
		[[nodiscard]] static std::optional<std::vector<UnloadedModule>> Query(uint32_t pid);
		// the entries in a captured trace (count entries of elementSize bytes, each starting as RTL_UNLOAD_EVENT_TRACE),
		// the unused ones (no base address) left out, newest first
		[[nodiscard]] static std::vector<UnloadedModule> Parse(void const* trace, size_t elementSize, size_t count);
	};
}
