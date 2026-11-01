#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// What keeps the system or the display awake, and what will wake it, as powercfg /requests and /waketimers show:
// NtPowerInformation's GetPowerRequestList (45) and WakeTimerList (50), undocumented, laid out as phnt's POWER_REQUEST
// V4 (Windows 10 RS1 on: a mask, six counts, then a DIAGNOSTIC_BUFFER) and WAKE_TIMER_INFO. Verified on Windows 11
// build 29698. Elevation needed (as for powercfg). The system's timer resolution comes from NtQueryTimerResolution.
//

namespace WinSys {
	enum class PowerRequestType { Display, System, AwayMode, Execution, PerfBoost, ActiveLockScreen, _Count };
	enum class PowerRequester { Driver, Process, Service };

	struct PowerRequestSource {
		PowerRequester Kind{ PowerRequester::Driver };
		std::wstring Name;			// a process's or service host's image path (a DOS path when it maps), a driver's device description
		std::wstring DevicePath;	// a driver's device instance path
		uint32_t ProcessId{ 0 };
		std::wstring ServiceName;	// a service's, from its tag (empty if it can't be resolved)
		std::wstring Reason;		// the requester's text: simple, or a resource string with its substitutions
	};

	struct PowerRequest : PowerRequestSource {
		uint32_t Counts[(int)PowerRequestType::_Count]{};	// how many times each type is requested (none: not active)
		[[nodiscard]] bool IsActive() const;
	};

	struct WakeTimer : PowerRequestSource {
		int64_t DueTime{ 0 };	// FILETIME (UTC) it expires at
		uint32_t PeriodMs{ 0 };	// 0: once
	};

	struct TimerResolution {
		uint32_t Coarsest{ 0 }, Finest{ 0 }, Current{ 0 };	// 100 ns units (15.625 ms is 156250)
	};

	struct PowerRequests final {
		// activeOnly: only requests with a count (the others are created but not set). Nothing, with the last error set,
		// if the list can't be read (ERROR_ACCESS_DENIED without elevation)
		[[nodiscard]] static std::optional<std::vector<PowerRequest>> Enum(bool activeOnly = true);
		[[nodiscard]] static std::optional<std::vector<WakeTimer>> EnumWakeTimers();
		[[nodiscard]] static std::optional<TimerResolution> GetTimerResolution();
		[[nodiscard]] static PCWSTR TypeName(PowerRequestType type);

		// the lists' parsing, apart from the queries (for the tests, and buffers kept from elsewhere): the request list
		// (a count, offsets from the start, the entries) and the wake timer list (entries linked by their offsets, the
		// time left in each made a FILETIME from now). Bad offsets and counts are skipped, not read past the buffer
		[[nodiscard]] static std::vector<PowerRequest> ParseRequestList(uint8_t const* buffer, size_t size, bool activeOnly);
		[[nodiscard]] static std::vector<WakeTimer> ParseWakeTimers(uint8_t const* buffer, size_t size, int64_t now);
	};
}
