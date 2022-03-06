// MainFrm.cpp : implmentation of the CMainFrame class
//
/////////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "resource.h"
#include "AboutDlg.h"
#include "ProcessesView.h"
#include "MainFrm.h"
#include "ServicesView.h"
#include "PerfView.h"
#include "IconHelper.h"
#include "SecurityHelper.h"
#include "ThemeHelper.h"

using namespace WinSys;

const int WINDOW_MENU_POSITION = 4;

BOOL CMainFrame::PreTranslateMessage(MSG* pMsg) {
	if (CFrameWindowImpl<CMainFrame>::PreTranslateMessage(pMsg))
		return TRUE;

	return m_view.PreTranslateMessage(pMsg);
}

BOOL CMainFrame::OnIdle() {
	return FALSE;
}

void CMainFrame::InitMenu() {
	const struct {
		UINT cmd;
		UINT id;
		HICON hIcon = nullptr;
	} icons[] = {
		{ ID_FILE_RUNASADMINISTRATOR, 0, IconHelper::GetShieldIcon() },
		{ ID_OPTIONS_ALWAYSONTOP, IDI_PIN },
		{ ID_VIEW_REFRESH, IDI_REFRESH },
		{ ID_TAB_PROCESSES, IDI_PROCESSES },
		{ ID_TAB_PERFORMANCE, IDI_PERF },
		{ ID_TAB_SERVICES, IDI_SERVICES },
		{ ID_PROCESS_COLUMNS, IDI_COLUMNS },
		{ ID_PROCESS_COLORS, IDI_COLORS },
		{ ID_PROCESS_KILL, IDI_DELETE },
	};

	for (auto& icon : icons) {
		auto hIcon = icon.id ? AtlLoadIconImage(icon.id, 0, 16, 16) : icon.hIcon;
		AddCommand(icon.cmd, hIcon);
	}
}

void CMainFrame::CreateTabs() {
	UINT icons[] = { IDI_PROCESSES, IDI_PERF, IDI_SERVICES };
	CImageList images;
	images.Create(16, 16, ILC_COLOR32 | ILC_MASK, 4, 4);
	for (auto icon : icons)
		images.AddIcon(AtlLoadIconImage(icon, 0, 16, 16));
	m_view.SetImageList(images);

	IView* views[] = {
		new CProcessesView(this),
		new CPerfView(this),
		new CServicesView(this),
	};
	int icon = 0;
	for (auto view : views) {
		view->CreateView(m_view);
		m_view.AddPage(view->GetHwnd(), view->GetTitle(), icon++, view);
	}
}

void CMainFrame::ActivatePage(int page) {
	if (m_CurrentTab >= 0)
		((IView*)m_view.GetPageData(m_CurrentTab))->PageActivated(false);
	m_CurrentTab = page;
	UISetRadioMenuItem(ID_TAB_PROCESSES + page, ID_TAB_PROCESSES, ID_TAB_SERVICES);
	((IView*)m_view.GetPageData(m_CurrentTab))->PageActivated(true);
}

LRESULT CMainFrame::OnTimer(UINT, WPARAM, LPARAM, BOOL&) {
	return 0;
}

LRESULT CMainFrame::OnShowWindow(UINT, WPARAM, LPARAM, BOOL&) {
	static bool show = false;
	if (!show) {
		show = true;
		auto wp = AppSettings::Get().MainWindowPlacement();
		SetWindowPlacement(&wp);
	}
	return 0;
}

LRESULT CMainFrame::OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	auto& settings = AppSettings::Get();
	auto loaded = settings.LoadFromKey(L"Software\\ScorpioSoftware\\TaskMgrX");

	InitDarkTheme();
	ThemeHelper::SetCurrentTheme(m_DefaultTheme);
	CreateSimpleStatusBar();
	m_sb.SubclassWindow(m_hWndStatusBar);

	m_view.m_bTabCloseButton = false;
	m_hWndClient = m_view.Create(m_hWnd, rcDefault, nullptr, 
		WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN, WS_EX_STATICEDGE);

	// register object for message filtering and idle updates
	auto pLoop = _Module.GetMessageLoop();
	ATLASSERT(pLoop);
	pLoop->AddMessageFilter(this);
	pLoop->AddIdleHandler(this);

	CMenuHandle menuMain = GetMenu();
	if (SecurityHelper::IsRunningElevated()) {
		menuMain.GetSubMenu(0).DeleteMenu(0, MF_BYPOSITION);
		menuMain.GetSubMenu(0).DeleteMenu(0, MF_BYPOSITION);
	}
	SetCheckIcon(AtlLoadIconImage(IDI_CHECK, 0, 16, 16), AtlLoadIconImage(IDI_RADIO, 0, 16, 16));
	AddMenu(menuMain);
	UIAddMenu(menuMain);

	UISetCheck(ID_VIEW_STATUS_BAR, 1);

	CreateTabs();
	InitMenu();
	m_view.SetActivePage(settings.InitialTab());

	if (loaded) {
		if (settings.Theme() == L"Dark")
			SetDarkMode(true);
		if (settings.AlwaysOnTop())
			ToggleAlwaysOnTop();
	}

	return 0;
}

LRESULT CMainFrame::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled) {
	auto& settings = AppSettings::Get();
	WINDOWPLACEMENT wp{ sizeof(wp) };
	GetWindowPlacement(&wp);
	settings.MainWindowPlacement(wp);
	settings.Save();

	// unregister message filtering and idle updates
	CMessageLoop* pLoop = _Module.GetMessageLoop();
	ATLASSERT(pLoop != nullptr);
	pLoop->RemoveMessageFilter(this);
	pLoop->RemoveIdleHandler(this);

	bHandled = FALSE;
	return 1;
}

LRESULT CMainFrame::OnFileExit(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	PostMessage(WM_CLOSE);
	return 0;
}

LRESULT CMainFrame::OnViewStatusBar(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	bool bVisible = !::IsWindowVisible(m_hWndStatusBar);
	::ShowWindow(m_hWndStatusBar, bVisible ? SW_SHOWNOACTIVATE : SW_HIDE);
	UISetCheck(ID_VIEW_STATUS_BAR, bVisible);
	UpdateLayout();
	return 0;
}

LRESULT CMainFrame::OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	CAboutDlg dlg;
	dlg.DoModal();
	return 0;
}

LRESULT CMainFrame::OnWindowActivate(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	int nPage = wID - ID_TAB_PROCESSES;
	m_view.SetActivePage(nPage);
	ActivatePage(nPage);

	return 0;
}

LRESULT CMainFrame::OnPageActivated(int, LPNMHDR, BOOL&) {
	if (m_view.GetActivePage() >= 0) {
		ActivatePage(m_view.GetActivePage());
	}
	return 0;
}

HWND CMainFrame::GetHwnd() const {
	return m_hWnd;
}

BOOL CMainFrame::TrackPopupMenu(HMENU hMenu, DWORD flags, int x, int y) {
	return ShowContextMenu(hMenu, flags, x, y);
}

CUpdateUIBase& CMainFrame::GetUI() {
	return *this;
}

LRESULT CMainFrame::OnRunAsAdmin(WORD, WORD, HWND, BOOL&) {
	if (SecurityHelper::RunElevated())
		SendMessage(WM_CLOSE);
	return 0;
}

void CMainFrame::InitDarkTheme() {
	m_DarkTheme.BackColor = m_DarkTheme.SysColors[COLOR_WINDOW] = RGB(32, 32, 32);
	m_DarkTheme.TextColor = m_DarkTheme.SysColors[COLOR_WINDOWTEXT] = RGB(248, 248, 248);
	m_DarkTheme.SysColors[COLOR_HIGHLIGHT] = RGB(10, 10, 160);
	m_DarkTheme.SysColors[COLOR_HIGHLIGHTTEXT] = RGB(240, 240, 240);
	m_DarkTheme.SysColors[COLOR_MENUTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_CAPTIONTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_BTNFACE] = m_DarkTheme.BackColor;
	m_DarkTheme.SysColors[COLOR_BTNTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_3DLIGHT] = RGB(192, 192, 192);
	m_DarkTheme.SysColors[COLOR_BTNHIGHLIGHT] = RGB(192, 192, 192);
	m_DarkTheme.SysColors[COLOR_CAPTIONTEXT] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_3DSHADOW] = m_DarkTheme.TextColor;
	m_DarkTheme.SysColors[COLOR_SCROLLBAR] = m_DarkTheme.BackColor;
	m_DarkTheme.Name = L"Dark";
	m_DarkTheme.Menu.BackColor = m_DarkTheme.BackColor;
	m_DarkTheme.Menu.TextColor = m_DarkTheme.TextColor;
}

LRESULT CMainFrame::OnAlwaysOnTop(WORD, WORD id, HWND, BOOL&) {
	auto topmost = ToggleAlwaysOnTop();
	AppSettings::Get().AlwaysOnTop(topmost);
	return 0;
}

bool CMainFrame::ToggleAlwaysOnTop() {
	auto style = GetExStyle() ^ WS_EX_TOPMOST;
	bool topmost = style & WS_EX_TOPMOST;
	SetWindowPos(topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	UISetCheck(ID_OPTIONS_ALWAYSONTOP, topmost);
	return topmost;
}

LRESULT CMainFrame::OnToggleDarkMode(WORD, WORD, HWND, BOOL&) {
	m_DarkMode = !m_DarkMode;
	SetDarkMode(m_DarkMode);
	AppSettings::Get().Theme((PCWSTR)ThemeHelper::GetCurrentTheme()->Name);

	return 0;
}

void CMainFrame::SetDarkMode(bool dark) {
	m_DarkMode = dark;
	ThemeHelper::SetCurrentTheme(m_DarkMode ? m_DarkTheme : m_DefaultTheme, m_hWnd);
	ThemeHelper::UpdateMenuColors(*this, m_DarkMode);
	UpdateMenu(GetMenu(), true);
	UISetCheck(ID_OPTIONS_DARKMODE, m_DarkMode);
}
