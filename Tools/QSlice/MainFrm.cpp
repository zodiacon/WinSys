// MainFrm.cpp : implmentation of the CMainFrame class
//
/////////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "resource.h"
#include "aboutdlg.h"
#include "View.h"
#include "MainFrm.h"
#include "IconHelper.h"
#include "SecurityHelper.h"
#include "ThemeHelper.h"

using namespace WinSys;

BOOL CMainFrame::PreTranslateMessage(MSG* pMsg) {
	if (CFrameWindowImpl<CMainFrame>::PreTranslateMessage(pMsg))
		return TRUE;

	return m_view.PreTranslateMessage(pMsg);
}

BOOL CMainFrame::OnIdle() {
	return FALSE;
}

void CMainFrame::InitDarkTheme() {
	m_DarkTheme.BackColor = m_DarkTheme.SysColors[COLOR_WINDOW] = RGB(32, 32, 32);
	m_DarkTheme.TextColor = m_DarkTheme.SysColors[COLOR_WINDOWTEXT] = RGB(248, 248, 248);
	m_DarkTheme.SysColors[COLOR_HIGHLIGHT] = RGB(32, 32, 255);
	m_DarkTheme.SysColors[COLOR_HIGHLIGHTTEXT] = RGB(240, 240, 240);
	m_DarkTheme.SysColors[COLOR_MENUTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_CAPTIONTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_BTNFACE] = RGB(16, 16, 96);
	m_DarkTheme.SysColors[COLOR_BTNTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_3DLIGHT] = RGB(192, 192, 192);
	m_DarkTheme.SysColors[COLOR_BTNHIGHLIGHT] = RGB(192, 192, 192);
	m_DarkTheme.SysColors[COLOR_CAPTIONTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_3DSHADOW] = m_DarkTheme.TextColor;
	m_DarkTheme.Name = L"Dark";
	m_DarkTheme.Menu.BackColor = m_DarkTheme.BackColor;
	m_DarkTheme.Menu.TextColor = m_DarkTheme.TextColor;
}

LRESULT CMainFrame::OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	m_hWndClient = m_view.Create(m_hWnd, rcDefault, nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN, WS_EX_STATICEDGE);
	InitDarkTheme();

	// register object for message filtering and idle updates
	auto pLoop = _Module.GetMessageLoop();
	ATLASSERT(pLoop);
	pLoop->AddMessageFilter(this);
	pLoop->AddIdleHandler(this);

	SetCheckIcon(AtlLoadIconImage(IDI_CHECK, 0, 16, 16), AtlLoadIconImage(IDI_RADIO, 0, 16, 16));
	CMenuHandle menu = GetMenu();
	if (SecurityHelper::IsRunningElevated()) {
		menu.GetSubMenu(0).DeleteMenu(0, MF_BYPOSITION);
		menu.GetSubMenu(0).DeleteMenu(0, MF_BYPOSITION);
	}
	UIAddMenu(menu);
	AddMenu(menu);
	AddCommand(ID_FILE_RUNASADMINISTRATOR, IconHelper::GetShieldIcon());
	UISetRadioMenuItem(ID_UPDATESPEED_FAST + m_IntervalIndex, ID_UPDATESPEED_FAST, ID_UPDATESPEED_VERYSLOW);

	return 0;
}

LRESULT CMainFrame::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled) {
	// unregister message filtering and idle updates
	CMessageLoop* pLoop = _Module.GetMessageLoop();
	pLoop->RemoveMessageFilter(this);
	pLoop->RemoveIdleHandler(this);

	bHandled = FALSE;
	return 1;
}

LRESULT CMainFrame::OnFileExit(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	PostMessage(WM_CLOSE);
	return 0;
}

LRESULT CMainFrame::OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	CAboutDlg dlg;
	dlg.DoModal();
	return 0;
}

LRESULT CMainFrame::OnAlwaysOnTop(WORD, WORD id, HWND, BOOL&) {
	auto style = GetExStyle() ^ WS_EX_TOPMOST;
	bool topmost = style & WS_EX_TOPMOST;
	SetWindowPos(topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	UISetCheck(id, topmost);

	return 0;
}

LRESULT CMainFrame::OnPauseResume(WORD, WORD, HWND, BOOL&) {
	bool pause = !m_view.ToggleRunning();
	UISetCheck(ID_VIEW_PAUSE, pause);
	return 0;
}

LRESULT CMainFrame::OnRunAsAdmin(WORD, WORD, HWND, BOOL&) {
	if (SecurityHelper::RunElevated())
		SendMessage(WM_CLOSE);
	return 0;
}

LRESULT CMainFrame::OnToggleDarkMode(WORD, WORD, HWND, BOOL& handled) {
	m_DarkMode = !m_DarkMode;
	ThemeHelper::SetCurrentTheme(m_DarkMode ? m_DarkTheme : m_DefaultTheme, m_hWnd);
	ThemeHelper::UpdateMenuColors(*this, m_DarkMode);
	UpdateMenu(GetMenu(), true);
	UISetCheck(ID_OPTIONS_DARKMODE, m_DarkMode);

	return 0;
}

LRESULT CMainFrame::OnUpdateInterval(WORD /*wNotifyCode*/, WORD id, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	m_IntervalIndex = id - ID_UPDATESPEED_FAST;
	UISetRadioMenuItem(ID_UPDATESPEED_FAST + m_IntervalIndex, ID_UPDATESPEED_FAST, ID_UPDATESPEED_VERYSLOW);
	m_view.SetUpdateInterval(s_Intervals[m_IntervalIndex]);

	return 0;
}

