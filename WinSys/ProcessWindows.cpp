#include "pch.h"
#include "ProcessWindows.h"

using namespace WinSys;

namespace {
	WindowInfo Read(HWND hWnd, int parent) {
		WindowInfo w;
		w.Handle = hWnd;
		w.Parent = parent;
		DWORD pid = 0;
		w.ThreadId = ::GetWindowThreadProcessId(hWnd, &pid);
		w.ProcessId = pid;
		WCHAR text[256];
		if (int len = ::GetClassName(hWnd, text, _countof(text)); len > 0)
			w.ClassName.assign(text, len);
		// sends no message, unlike GetWindowText
		if (int len = ::InternalGetWindowText(hWnd, text, _countof(text)); len > 0)
			w.Text.assign(text, len);
		w.Owner = ::GetWindow(hWnd, GW_OWNER);
		w.Style = (uint32_t)::GetWindowLongPtr(hWnd, GWL_STYLE);
		w.ExStyle = (uint32_t)::GetWindowLongPtr(hWnd, GWL_EXSTYLE);
		w.ClassStyle = (uint32_t)::GetClassLongPtr(hWnd, GCL_STYLE);
		if (w.Style & WS_CHILD)
			w.Id = (uintptr_t)::GetWindowLongPtr(hWnd, GWLP_ID);
		::GetWindowRect(hWnd, &w.Rect);
		::GetClientRect(hWnd, &w.ClientRect);
		w.Dpi = ::GetDpiForWindow(hWnd);
		w.Visible = ::IsWindowVisible(hWnd);
		w.Enabled = ::IsWindowEnabled(hWnd);
		w.Minimized = ::IsIconic(hWnd);
		w.Maximized = ::IsZoomed(hWnd);
		w.Unicode = ::IsWindowUnicode(hWnd);
		if (parent < 0)
			w.Hung = ::IsHungAppWindow(hWnd);
		return w;
	}

	// the window and its descendants, depth first
	void AddTree(std::vector<WindowInfo>& windows, HWND hWnd, int parent, bool messageOnly) {
		auto index = (int)windows.size();
		windows.push_back(Read(hWnd, parent));
		windows.back().MessageOnly = messageOnly;
		for (auto child = ::GetWindow(hWnd, GW_CHILD); child; child = ::GetWindow(child, GW_HWNDNEXT))
			AddTree(windows, child, index, false);
	}

	DWORD ProcessOf(HWND hWnd) {
		DWORD pid = 0;
		::GetWindowThreadProcessId(hWnd, &pid);
		return pid;
	}
}

std::vector<WindowInfo> ProcessWindows::Enum(uint32_t pid) {
	// the top-level windows first, in Z order (then the tree is built: a window may go while it's read)
	std::vector<HWND> topLevel;
	struct Context {
		uint32_t Pid;
		std::vector<HWND>* Windows;
	} context{ pid, &topLevel };
	::EnumWindows([](HWND hWnd, LPARAM param) -> BOOL {
		auto& ctx = *reinterpret_cast<Context*>(param);
		if (ProcessOf(hWnd) == ctx.Pid)
			ctx.Windows->push_back(hWnd);
		return TRUE;
		}, reinterpret_cast<LPARAM>(&context));

	std::vector<WindowInfo> windows;
	for (auto hWnd : topLevel)
		AddTree(windows, hWnd, -1, false);
	// message-only windows aren't top-level: they're HWND_MESSAGE's children
	for (HWND hWnd = nullptr; (hWnd = ::FindWindowEx(HWND_MESSAGE, hWnd, nullptr, nullptr)) != nullptr; )
		if (ProcessOf(hWnd) == pid)
			AddTree(windows, hWnd, -1, true);
	return windows;
}

bool ProcessWindows::Show(HWND hWnd, bool show) {
	if (!::IsWindow(hWnd)) {
		::SetLastError(ERROR_INVALID_WINDOW_HANDLE);
		return false;
	}
	// its return value is the previous visibility, not success
	::ShowWindowAsync(hWnd, show ? SW_SHOW : SW_HIDE);
	return true;
}

bool ProcessWindows::BringToFront(HWND hWnd) {
	if (!::IsWindow(hWnd)) {
		::SetLastError(ERROR_INVALID_WINDOW_HANDLE);
		return false;
	}
	if (::IsIconic(hWnd))
		::ShowWindowAsync(hWnd, SW_RESTORE);
	if (!::SetForegroundWindow(hWnd)) {
		::SetLastError(ERROR_ACCESS_DENIED);
		return false;
	}
	return true;
}

bool ProcessWindows::Close(HWND hWnd) {
	return ::PostMessage(hWnd, WM_CLOSE, 0, 0);
}
