#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "ProcessWindows.h"

//
// Window stations and desktops, read-only:
// - every session's window stations, from the object namespace (\Sessions\<n>\Windows\WindowStations; \Windows\
//   WindowStations is session 0's under another name); a process can open only its own session's, so the others are
//   listed by name
// - for the caller's session: each station's flags (visible: WSF_VISIBLE) and desktops (EnumDesktopsW), and each
//   desktop's heap size and whether it's the input desktop, when it can be opened (the Winlogon desktop only for
//   SYSTEM)
// - the top-level windows of a desktop of the caller's own window station (EnumDesktopWindows; reading nothing that
//   sends a message, as ProcessWindows). Another station's desktops would need the process's window station switched,
//   which a GUI process shouldn't do, so their windows aren't listed.
//

namespace WinSys {
	struct DesktopInfo {
		std::wstring Name;
		bool Opened{ false };	// it could be opened (its heap and input state are known)
		uint32_t HeapSizeKB{ 0 };
		bool Input{ false };	// the input desktop (the one receiving input now)
	};

	struct WindowStationInfo {
		uint32_t Session{ 0 };
		std::wstring Name;
		bool CurrentSession{ false };	// the caller's: its details below are known
		bool Own{ false };		// the caller's own window station (its desktops' windows can be listed)
		bool Opened{ false };	// it could be opened
		bool Visible{ false };	// WSF_VISIBLE: interactive (WinSta0)
		std::vector<DesktopInfo> Desktops;
	};

	struct WindowStations final {
		// nothing (with the last error set) if the namespace can't be read
		[[nodiscard]] static std::optional<std::vector<WindowStationInfo>> Enum();
		// a desktop of the caller's own window station: its top-level windows in Z order (no child windows; message-only
		// windows aren't on a desktop); nothing, with the last error, if it can't be opened or isn't the caller's station's
		[[nodiscard]] static std::optional<std::vector<WindowInfo>> EnumDesktopWindows(std::wstring const& desktop);
	};
}
