#pragma once

struct IMainFrame abstract {
	virtual HWND GetHwnd() const = 0;
	virtual BOOL TrackPopupMenu(HMENU hMenu, DWORD flags, int x, int y) = 0;
	virtual CUpdateUIBase& GetUI() = 0;
};

struct IView {
	virtual HWND CreateView(HWND hParent, DWORD style = WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN, DWORD exstyle = 0) = 0;
	virtual void PageActivated(bool active) {}
	virtual bool ProcessCommand(UINT cmd) {
		return false;
	}
	virtual HWND GetHwnd() const = 0;
	virtual CString GetTitle() const = 0;
};
