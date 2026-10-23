#pragma once

#include <cstdint>
#include <string>
#include <vector>

//
// A process's windows: its top-level windows (message-only ones too) with their child windows, as a tree, and the
// actions a tool takes on them. Everything is read without sending a message to the windows (InternalGetWindowText,
// not GetWindowText), so a hung process can't hang the caller. Windows on other desktops aren't seen.
//

namespace WinSys {
	struct WindowInfo {
		HWND Handle{ nullptr };
		int Parent{ -1 };	// the parent's index in the list; -1 for a top-level window
		HWND Owner{ nullptr };
		uint32_t ThreadId{ 0 }, ProcessId{ 0 };
		std::wstring ClassName, Text;
		uint32_t Style{ 0 }, ExStyle{ 0 }, ClassStyle{ 0 };
		uintptr_t Id{ 0 };	// a child window's (GWLP_ID)
		RECT Rect{}, ClientRect{};	// the window's in screen coordinates; the client area's in its own
		uint32_t Dpi{ 0 };
		bool Visible{ false }, Enabled{ false }, Minimized{ false }, Maximized{ false }, Unicode{ false };
		bool Hung{ false };			// a top-level window that hasn't taken messages for 5 seconds (IsHungAppWindow)
		bool MessageOnly{ false };	// a child of HWND_MESSAGE
	};

	struct ProcessWindows final {
		// the process's top-level windows in Z order, then its message-only windows, each followed by its child windows
		// (depth first; a child of another process's is listed too, as it's in the window)
		[[nodiscard]] static std::vector<WindowInfo> Enum(uint32_t pid);

		// ShowWindowAsync, so a hung window doesn't hold up the caller; false with the last error
		static bool Show(HWND hWnd, bool show);
		// restored if it's minimized, then made the foreground window (the caller must be allowed to: the foreground
		// process, as a tool that was just clicked is)
		static bool BringToFront(HWND hWnd);
		// posts WM_CLOSE: the window decides (it may ask, or ignore it)
		static bool Close(HWND hWnd);
	};
}
