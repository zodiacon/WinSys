#include "pch.h"
#include "PerfView.h"

void CPerfView::OnFinalMessage(HWND) {
	delete this;
}

CString CPerfView::GetTitle() const {
	return L"Performance";
}

LRESULT CPerfView::OnCreate(UINT, WPARAM, LPARAM, BOOL&) {
	return LRESULT();
}
