// View.cpp : implementation of the CProcessesView class
//
/////////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "resource.h"
#include "ProcessesView.h"

BOOL CProcessesView::PreTranslateMessage(MSG* pMsg) {
	pMsg;
	return FALSE;
}

void CProcessesView::OnFinalMessage(HWND /*hWnd*/) {
	delete this;
}

LRESULT CProcessesView::OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	//TODO: Add your drawing code here

	return 0;
}

CString CProcessesView::GetTitle() const {
	return L"Processes";
}
