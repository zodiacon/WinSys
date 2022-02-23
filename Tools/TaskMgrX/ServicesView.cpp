#include "pch.h"
#include "ServicesView.h"

void CServicesView::OnFinalMessage(HWND) {
	delete this;
}

CString CServicesView::GetTitle() const {
	return L"Services";
}

LRESULT CServicesView::OnCreate(UINT, WPARAM, LPARAM, BOOL&) {
	return LRESULT();
}
