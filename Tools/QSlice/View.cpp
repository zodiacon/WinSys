// View.cpp : implementation of the CView class
//
/////////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "resource.h"
#include "View.h"
#include "SortHelper.h"
#include "ImageIconCache.h"
#include "ThemeHelper.h"
#define __cpp_lib_format
#include <concepts>
#include <format>

using namespace WinSys;

bool CView::ToggleRunning() {
	m_Running = !m_Running;
	if (m_Running)
		SetTimer(1, m_Interval);
	else
		KillTimer(1);
	return m_Running;
}

void CView::SetUpdateInterval(int interval) {
	m_Interval = interval;
	if (m_Running)
		SetTimer(1, interval);
}

BOOL CView::PreTranslateMessage(MSG* pMsg) {
	pMsg;
	return FALSE;
}

CString CView::GetColumnText(HWND, int row, int col) const {
	if (row >= m_Items.size())
		return L"";

	auto& p = m_Items[row];

	switch (col) {
		case 0: return p->GetImageName().c_str();
		case 1: return std::to_wstring(p->Id).c_str();
		case 2: return p->CPU > 0 && !p->Deleted ? std::format(L"{:6.2f}", p->CPU / 10000.0f).c_str() : L"";
	}
	return L"";
}

int CView::GetRowImage(HWND, int row, int col) const {
	if (row >= m_Items.size())
		return -1;

	auto& p = m_Items[row];
	if (p->Image < 0) {
		p->Image = 0;
		Process process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p->Id));
		if (process) {
			auto path = process.GetFullImageName();
			if (!path.empty())
				p->Image = ImageIconCache::Get().GetIcon(path);
		}
	}
	return p->Image;
}

void CView::DoSort(SortInfo const* si) {
	auto compare = [&](auto p1, auto p2) {
		switch (si->SortColumn) {
			case 0: return SortHelper::Sort(p1->GetImageName(), p2->GetImageName(), si->SortAscending);
			case 1: return SortHelper::Sort(p1->Id, p2->Id, si->SortAscending);
			case 2: 
			case 3:
				return SortHelper::Sort(p1->CPU, p2->CPU, si->SortAscending);
		}
		return false;
	};

	std::sort(m_Items.begin(), m_Items.end(), compare);
}

void CView::PreSort(HWND) {
	if (m_SelectedPid != -1)
		return;

	int selected = m_List.GetSelectedIndex();
	if (selected >= 0 && selected < m_Items.size())
		m_SelectedPid = m_Items[selected]->Id;
	else
		m_SelectedPid = -1;
}

void CView::PostSort(HWND) {
	if (m_SelectedPid != -1) {
		SelectPid(m_SelectedPid);
		m_SelectedPid = -1;
	}
}

DWORD CView::OnPrePaint(int, LPNMCUSTOMDRAW cd) {
	return CDRF_NOTIFYITEMDRAW;
}

DWORD CView::OnItemPrePaint(int, LPNMCUSTOMDRAW cd) {
	auto lv = (NMLVCUSTOMDRAW*)cd;
	lv->clrTextBk = CLR_INVALID;
	int row = (int)cd->dwItemSpec;
	if (row >= m_Items.size())
		return CDRF_SKIPPOSTPAINT;
	auto& p = m_Items[row];
	auto tick = GetTickCount64();
	if (p->Deleted) {
		lv->clrTextBk = RGB(255, 64, 0);
		if (tick >= p->TargetTime) {
			m_Deleted.insert(row);
		}
	}
	else if (p->New) {
		lv->clrTextBk = ThemeHelper::IsDefault() ? RGB(0, 255, 64) : RGB(0, 160, 64);
		if (tick >= p->TargetTime)
			p->New = false;
	}
	return CDRF_NOTIFYSUBITEMDRAW | CDRF_SKIPPOSTPAINT;
}

DWORD CView::OnSubItemPrePaint(int, LPNMCUSTOMDRAW cd) {
	auto lv = (NMLVCUSTOMDRAW*)cd;
	if (lv->iSubItem != 3)
		return CDRF_SKIPPOSTPAINT;

	int row = (int)cd->dwItemSpec;
	if (row >= m_Items.size())
		return CDRF_SKIPDEFAULT;

	auto p = m_Items[row].get();
	if (p->Deleted)
		return CDRF_SKIPDEFAULT;

	CDCHandle dc(cd->hdc);
	CRect rc(cd->rc);
	rc.DeflateRect(0, 1);
	int len = rc.Width() * p->CPU / 10000 / 100;
	int klen = rc.Width() * p->KernelCPU / 10000 / 100;
	ATLASSERT(len >= klen);
	rc.right = rc.left + klen;
	dc.FillSolidRect(&rc, p->Id ? RGB(255, 0, 0) : RGB(128, 128, 128));
	rc.left = rc.right;
	rc.right = rc.left + len - klen;
	dc.FillSolidRect(&rc, RGB(0, 0, 255));
	return CDRF_SKIPDEFAULT;
}

void CView::SelectPid(DWORD pid) {
	int count = (int)m_Items.size();
	for (int i = 0; i < count; i++)
		if (m_Items[i]->Id == pid) {
			m_List.SetItemState(i, LVIS_SELECTED, LVIS_SELECTED);
			ATLTRACE(L"Selecting PID: %u (%i)\n", pid, i);
			break;
		}
}

LRESULT CView::OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	m_List.Create(m_hWnd, rcDefault, nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS |
		LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS);

	m_List.SetExtendedListViewStyle(LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT);
	CImageList images;
	images.Create(16, 16, ILC_COLOR32 | ILC_MASK, 64, 64);
	images.AddIcon(AtlLoadSysIcon(IDI_APPLICATION));
	m_List.SetImageList(images, LVSIL_SMALL);
	ImageIconCache::Get().SetImageList(images);

	auto count = m_pm.EnumProcesses();
	m_Items = m_pm.GetProcesses();

	auto cm = GetColumnManager(m_List);
	cm->AddColumn(L"Name", LVCFMT_LEFT, 240);
	cm->AddColumn(L"PID", LVCFMT_RIGHT, 80);
	cm->AddColumn(L"CPU %", LVCFMT_RIGHT, 80);
	cm->AddColumn(L"CPU %", LVCFMT_LEFT, 400);
	cm->UpdateColumns();

	m_List.SetItemCount((int)count);
	SetTimer(1, 1000);

	return 0;
}

LRESULT CView::OnSize(UINT, WPARAM, LPARAM lp, BOOL&) {
	auto cx = GET_X_LPARAM(lp), cy = GET_Y_LPARAM(lp);
	if (m_List)
		m_List.MoveWindow(0, 0, cx, cy);
	return 0;
}

LRESULT CView::OnTimer(UINT, WPARAM id, LPARAM, BOOL&) {
	if (id == 1) {
		int selected = m_List.GetSelectedIndex();
		if (selected >= 0 && selected < m_Items.size())
			m_SelectedPid = m_Items[selected]->Id;

		auto count = m_pm.EnumProcesses();
		auto tick = GetTickCount64();
		for (auto& p : m_pm.GetNewProcesses()) {
			p->New = true;
			p->TargetTime = tick + 2000;
			m_Items.push_back(p);
		}
		for (auto& p : m_pm.GetTerminatedProcesses()) {
			p->Deleted = true;
			p->TargetTime = tick + 2000;
		}

		if (!m_Deleted.empty()) {
			int offset = 0;
			for (auto& i : m_Deleted) {
				m_Items.erase(m_Items.begin() + i - offset);
				offset++;
			}
			m_Deleted.clear();
		}
		m_List.SetItemCountEx((int)m_Items.size(), LVSICF_NOSCROLL | LVSICF_NOINVALIDATEALL);
		auto si = GetSortInfo(m_List);
		if (si)
			Sort(si);
		m_List.RedrawItems(m_List.GetTopIndex(), m_List.GetTopIndex() + m_List.GetCountPerPage());
	}
	return 0;
}
