#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// The running ETW sessions and the providers enabled in them, read-only:
// - the sessions from QueryAllTraces (their properties: mode, buffers, events and buffers lost, log file)
// - the providers from EnumerateTraceGuidsEx: every registered provider's instances (the processes that registered
//   it) and, for each, the sessions (by logger ID) that enabled it, with the level and keywords; a provider's name from
//   TdhEnumerateProviders (manifest and MOF providers; others show their GUID only)
// The kernel's own loggers (NT Kernel Logger, the system loggers) take events by flags, not from providers, so they
// list none. Most sessions need administrator rights (or Performance Log Users) to be queried.
//

namespace WinSys {
	struct EtwSessionProvider {
		GUID Id{};
		std::wstring Name;			// empty if it isn't registered with TDH
		uint8_t Level{ 0 };			// TRACE_LEVEL_*
		uint64_t MatchAnyKeyword{ 0 }, MatchAllKeyword{ 0 };
		std::vector<uint32_t> Pids;	// the processes whose instance of it the session enabled (0: the kernel)
	};

	struct EtwSession {
		uint32_t LoggerId{ 0 };
		std::wstring Name;
		std::wstring LogFile;		// empty for a real-time-only session
		uint32_t LogFileMode{ 0 };	// EVENT_TRACE_*_MODE flags
		std::wstring Mode;			// those flags in words: "Real time", "File (circular)"...
		uint32_t BufferSizeKB{ 0 }, Buffers{ 0 }, FreeBuffers{ 0 }, MinimumBuffers{ 0 }, MaximumBuffers{ 0 };
		uint32_t EventsLost{ 0 }, BuffersWritten{ 0 }, LogBuffersLost{ 0 }, RealTimeBuffersLost{ 0 };
		uint32_t FlushTimer{ 0 };	// seconds
		uint32_t EnableFlags{ 0 };	// a kernel logger's EVENT_TRACE_FLAG_*
		std::vector<EtwSessionProvider> Providers;
	};

	struct EtwSessions final {
		// nothing (with the last error set) if the sessions can't be queried at all (ERROR_ACCESS_DENIED, not elevated)
		[[nodiscard]] static std::optional<std::vector<EtwSession>> Enum();
		[[nodiscard]] static std::wstring LevelName(uint8_t level);
	};
}
