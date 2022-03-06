// View.h : interface of the CView class
//
/////////////////////////////////////////////////////////////////////////////

#pragma once

#include "VirtualListView.h"
#include <WinSys.h>
#include "ProcessManager.h"

class CView : 
	public CWindowImpl<CView>,
	public CCustomDraw<CView>,
	public CVirtualListView<CView> {
public:
	DECLARE_WND_CLASS(NULL)

	bool ToggleRunning();
	void SetUpdateInterval(int interval);

	BOOL PreTranslateMessage(MSG* pMsg);

	CString GetColumnText(HWND, int row, int col) const;
	int GetRowImage(HWND, int row, int col) const;
	void DoSort(SortInfo const* si);
	void PreSort(HWND);
	void PostSort(HWND);

	DWORD OnPrePaint(int, LPNMCUSTOMDRAW cd);
	DWORD OnItemPrePaint(int, LPNMCUSTOMDRAW cd);
	DWORD OnSubItemPrePaint(int, LPNMCUSTOMDRAW cd);

protected:
	BEGIN_MSG_MAP(CView)
		MESSAGE_HANDLER(WM_TIMER, OnTimer)
		MESSAGE_HANDLER(WM_SIZE, OnSize)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		CHAIN_MSG_MAP(CCustomDraw<CView>)
		CHAIN_MSG_MAP(CVirtualListView<CView>)
	ALT_MSG_MAP(1)
	END_MSG_MAP()

private:
	void SelectPid(DWORD pid);
	struct ProcessInfoEx : WinSys::ProcessInfo {
		DWORD64 TargetTime;
		int Image{ -1 };
		bool New{ false };
		bool Deleted{ false };
	};

	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnSize(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnTimer(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);

	CListViewCtrl m_List;
	WinSys::ProcessManager<ProcessInfoEx> m_pm;
	std::vector<std::shared_ptr<ProcessInfoEx>> m_Items;
	std::set<int> m_Deleted;
	DWORD m_SelectedPid = -1;
	int m_Interval{ 1000 };
	bool m_Running{ true };
};
