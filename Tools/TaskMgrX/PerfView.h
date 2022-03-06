#pragma once

#include "Interfaces.h"
#include "ViewBase.h"
#include "CustomTabView.h"

class CPerfView : public CViewBase<CPerfView> {
public:
	using CViewBase::CViewBase;
	DECLARE_WND_CLASS(NULL)

	void OnFinalMessage(HWND /*hWnd*/) override;
	CString GetTitle() const override;

	BEGIN_MSG_MAP(CPerfView)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		CHAIN_MSG_MAP(CViewBase<CPerfView>)
	END_MSG_MAP()

private:
	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);

	CCustomTabView m_tabs;
};

