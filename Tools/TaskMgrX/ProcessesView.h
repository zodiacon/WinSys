// View.h : interface of the CView class
//
/////////////////////////////////////////////////////////////////////////////

#pragma once

#include "ViewBase.h"
#include "VirtualListView.h"
#include "ProcessInfo.h"
#include <set>
#include <ProcessManager.h>
#include "IListView.h"

class CProcessesView : 
	public CViewBase<CProcessesView>,
	public CCustomDraw<CProcessesView>,
	public CVirtualListView<CProcessesView> {
public:
	using CViewBase::CViewBase;
	DECLARE_WND_CLASS(NULL)

	BOOL PreTranslateMessage(MSG* pMsg);
	virtual void OnFinalMessage(HWND /*hWnd*/);
	CString GetTitle() const override;

protected:
	BEGIN_MSG_MAP(CProcessesView)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		CHAIN_MSG_MAP(CCustomDraw<CProcessesView>)
		CHAIN_MSG_MAP(CVirtualListView<CProcessesView>)
		CHAIN_MSG_MAP(CViewBase)
	END_MSG_MAP()

private:
	struct ProcessInfoEx : ProcessInfo {
	};

	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);

	CListViewCtrl m_List;
	CComPtr<IListView> m_spList;
	ProcessManager<ProcessInfoEx> m_pm;
	std::vector<std::shared_ptr<ProcessInfoEx>> m_Items;
	std::set<int> m_Deleted;
	DWORD m_SelectedPid = -1;
	int m_Interval{ 1000 };
	bool m_Running{ true };
};
