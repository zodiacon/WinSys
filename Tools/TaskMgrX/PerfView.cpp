#include "pch.h"
#include "PerfView.h"
#include "ServicesView.h"

void CPerfView::OnFinalMessage(HWND) {
	delete this;
}

CString CPerfView::GetTitle() const {
	return L"Performance";
}

LRESULT CPerfView::OnCreate(UINT, WPARAM, LPARAM, BOOL&) {
	m_hWndClient = m_tabs.Create(m_hWnd, rcDefault, nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN);

	return 0;
}
