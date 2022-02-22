// MainFrm.h : interface of the CMainFrame class
//
/////////////////////////////////////////////////////////////////////////////

#pragma once

#include "View.h"
#include "OwnerDrawnMenu.h"
#include "Theme.h"

class CMainFrame :
	public CFrameWindowImpl<CMainFrame>,
	public CAutoUpdateUI<CMainFrame>,
	public COwnerDrawnMenu<CMainFrame>,
	public CMessageFilter, 
	public CIdleHandler {
public:
	DECLARE_FRAME_WND_CLASS(NULL, IDR_MAINFRAME)

	virtual BOOL PreTranslateMessage(MSG* pMsg);
	virtual BOOL OnIdle();

	BEGIN_MSG_MAP(CMainFrame)
		COMMAND_ID_HANDLER(ID_APP_EXIT, OnFileExit)
		COMMAND_ID_HANDLER(ID_APP_ABOUT, OnAppAbout)
		COMMAND_ID_HANDLER(ID_VIEW_PAUSE, OnPauseResume)
		COMMAND_ID_HANDLER(ID_FILE_RUNASADMINISTRATOR, OnRunAsAdmin)
		COMMAND_ID_HANDLER(ID_OPTIONS_ALWAYSONTOP, OnAlwaysOnTop)
		COMMAND_ID_HANDLER(ID_OPTIONS_DARKMODE, OnToggleDarkMode)
		COMMAND_RANGE_HANDLER(ID_UPDATESPEED_FAST, ID_UPDATESPEED_VERYSLOW, OnUpdateInterval)
		if (uMsg == WM_COMMAND && m_view) {
			if (m_view.ProcessWindowMessage(hWnd, uMsg, wParam, lParam, lResult, 1))
				return TRUE;
		}
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		MESSAGE_HANDLER(WM_DESTROY, OnDestroy)
		CHAIN_MSG_MAP(CAutoUpdateUI<CMainFrame>)
		CHAIN_MSG_MAP(COwnerDrawnMenu<CMainFrame>)
		CHAIN_MSG_MAP(CFrameWindowImpl<CMainFrame>)
	END_MSG_MAP()

private:
	void InitDarkTheme();

	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled);
	LRESULT OnFileExit(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnAlwaysOnTop(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnPauseResume(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnRunAsAdmin(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnToggleDarkMode(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnUpdateInterval(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);

	CView m_view;
	Theme m_DarkTheme, m_DefaultTheme{ true };
	int m_IntervalIndex{ 1 };
	inline static int s_Intervals[4]{ 500, 1000, 2000, 5000 };
	bool m_DarkMode{ false };
};
