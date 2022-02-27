// View.cpp : implementation of the CProcessesView class
//
/////////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "resource.h"
#include "ProcessesView.h"
#include "ListViewhelper.h"
#include "ImageIconCache.h"
#include "Processes.h"
#include "SortHelper.h"
#include "StringHelper.h"
#include "Helpers.h"
#include "ThemeHelper.h"

#pragma comment(lib, "Version.lib")

BOOL CProcessesView::PreTranslateMessage(MSG* pMsg) {
	pMsg;
	return FALSE;
}

void CProcessesView::OnFinalMessage(HWND /*hWnd*/) {
	delete this;
}

LRESULT CProcessesView::OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	//ToolBarButtonInfo buttons[] = {
	//	{ ID_PROCESS_THREADS, IDI_THREAD, 0, L"Threads" },
	//	{ ID_HANDLES_SHOWHANDLEINPROCESS, IDI_HANDLES, 0, L"Handles" },
	//	{ ID_PROCESS_MODULES, IDI_DLL, 0, L"Modules" },
	//	{ ID_PROCESS_MEMORYMAP, IDI_DRAM, 0, L"Memory" },
	//	{ ID_PROCESS_HEAPS, IDI_HEAP, 0, L"Heaps" },
	//	{ 0 },
	//	{ ID_PROCESS_KILL, IDI_DELETE },
	//	{ 0 },
	//	{ ID_HEADER_COLUMNS, IDI_EDITCOLUMNS, 0, L"Columns" },
	//	{ 0 },
	//	{ ID_PROCESS_COLORS, IDI_COLORWHEEL, 0, L"Colors" },
	//};
	//CreateAndInitToolBar(buttons, _countof(buttons));

	m_hWndClient = m_List.Create(m_hWnd, rcDefault, nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS |
		LVS_OWNERDATA | LVS_SINGLESEL | LVS_REPORT);
	m_List.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP | LVS_EX_HEADERDRAGDROP);
	m_spList = ListViewHelper::GetIListView(m_List);
	ATLASSERT(m_spList);
	CImageList images;
	images.Create(16, 16, ILC_COLOR32 | ILC_MASK, 64, 64);
	images.AddIcon(AtlLoadSysIcon(IDI_APPLICATION));
	ImageIconCache::Get().SetImageList(images);
	m_List.SetImageList(images, LVSIL_SMALL);

	auto cm = GetColumnManager(m_List);
	cm->AddColumn(L"Name", LVCFMT_LEFT, 200, ColumnType::Name, ColumnFlags::Visible | ColumnFlags::Mandatory | ColumnFlags::Const);
	cm->AddColumn(L"Id", LVCFMT_RIGHT, 80, ColumnType::Id, ColumnFlags::Visible | ColumnFlags::Mandatory | ColumnFlags::Numeric | ColumnFlags::Const);
	cm->AddColumn(L"User Name", LVCFMT_LEFT, 200, ColumnType::UserName, ColumnFlags::Visible | ColumnFlags::Const);
	cm->AddColumn(L"Session", LVCFMT_RIGHT, 60, ColumnType::Session, ColumnFlags::Visible | ColumnFlags::Numeric | ColumnFlags::Const);
	cm->AddColumn(L"Performance\\CPU (%)", LVCFMT_RIGHT, 80, ColumnType::CPU, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\CPU Time", LVCFMT_RIGHT, 120, ColumnType::CPUTime, ColumnFlags::Numeric | ColumnFlags::Visible);
	cm->AddColumn(L"Parent", LVCFMT_LEFT, 180, ColumnType::Parent, ColumnFlags::Const);
	cm->AddColumn(L"Performance\\Base Priority", LVCFMT_LEFT, 80, ColumnType::BasePriority, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Priority Class", LVCFMT_LEFT, 120, ColumnType::PriorityClass, ColumnFlags::Visible);
	cm->AddColumn(L"Performance\\Threads", LVCFMT_RIGHT, 60, ColumnType::Threads, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Peak Threads", LVCFMT_RIGHT, 60, ColumnType::PeakThreads, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Handles", LVCFMT_RIGHT, 70, ColumnType::Handles, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Attributes", LVCFMT_LEFT, 100, ColumnType::Attributes, ColumnFlags::Visible | ColumnFlags::Const);
	cm->AddColumn(L"Image Path", LVCFMT_LEFT, 300, ColumnType::ImagePath, ColumnFlags::Const);
	cm->AddColumn(L"Create Time", LVCFMT_LEFT, 160, ColumnType::CreateTime, ColumnFlags::Visible | ColumnFlags::Numeric | ColumnFlags::Const);
	cm->AddColumn(L"Memory\\Commit (K)", LVCFMT_RIGHT, 110, ColumnType::Commit, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak Commit (K)", LVCFMT_RIGHT, 120, ColumnType::PeakCommit, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Working Set (K)", LVCFMT_RIGHT, 110, ColumnType::WorkingSet, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak WS (K)", LVCFMT_RIGHT, 120, ColumnType::PeakWorkingSet, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Virtual Size (K)", LVCFMT_RIGHT, 110, ColumnType::VirtualSize, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak Virtual Size (K)", LVCFMT_RIGHT, 120, ColumnType::PeakVirtualSize, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Paged Pool (K)", LVCFMT_RIGHT, 110, ColumnType::PagedPool, ColumnFlags::Numeric | ColumnFlags::Visible);
	cm->AddColumn(L"Memory\\Peak Paged (K)", LVCFMT_RIGHT, 110, ColumnType::PeakPagedPool, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Non Paged (K)", LVCFMT_RIGHT, 110, ColumnType::NonPagedPool, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak NPaged (K)", LVCFMT_RIGHT, 120, ColumnType::PeakNonPagedPool, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Kernel Time", LVCFMT_RIGHT, 120, ColumnType::KernelTime, ColumnFlags::Numeric | ColumnFlags::Visible);
	cm->AddColumn(L"Performance\\User Time", LVCFMT_RIGHT, 120, ColumnType::UserTime, ColumnFlags::Numeric | ColumnFlags::Visible);
	cm->AddColumn(L"Performance\\I/O Priority", LVCFMT_LEFT, 80, ColumnType::IoPriority, ColumnFlags::None);
	cm->AddColumn(L"Performance\\Memory Priority", LVCFMT_RIGHT, 80, ColumnType::MemoryPriority, ColumnFlags::Numeric);
	cm->AddColumn(L"Command Line", LVCFMT_LEFT, 250, ColumnType::CommandLine, ColumnFlags::Const);
	cm->AddColumn(L"Package Name", LVCFMT_LEFT, 250, ColumnType::PackageName, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"Job Object Id", LVCFMT_RIGHT, 100, ColumnType::JobId, ColumnFlags::Numeric | ColumnFlags::Const);
	cm->AddColumn(L"I/O\\I/O Read Bytes", LVCFMT_RIGHT, 120, ColumnType::ReadBytes, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Write Bytes", LVCFMT_RIGHT, 120, ColumnType::WriteBytes, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Other Bytes", LVCFMT_RIGHT, 120, ColumnType::OtherBytes, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Reads", LVCFMT_RIGHT, 90, ColumnType::ReadCount, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Writes", LVCFMT_RIGHT, 90, ColumnType::WriteCount, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Other", LVCFMT_RIGHT, 90, ColumnType::OtherCount, ColumnFlags::Numeric);
	//cm->AddColumn(L"GUI\\GDI Objects", LVCFMT_RIGHT, 90, ColumnFlags::Numeric);
	//cm->AddColumn(L"GUI\\User Objects", LVCFMT_RIGHT, 90, ColumnFlags::Numeric);
	//cm->AddColumn(L"GUI\\Peak GDI Objects", LVCFMT_RIGHT, 90, ColumnFlags::Numeric);
	//cm->AddColumn(L"GUI\\Peak User Objects", LVCFMT_RIGHT, 90, ColumnFlags::Numeric);
	cm->AddColumn(L"Token\\Integrity", LVCFMT_LEFT, 70, ColumnType::Integrity, ColumnFlags::Visible);
	cm->AddColumn(L"Token\\Elevated", LVCFMT_LEFT, 60, ColumnType::Elevated, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"Token\\Virtualization", LVCFMT_LEFT, 85, ColumnType::Virtualization, ColumnFlags::Visible);
	//cm->AddColumn(L"Window Title", LVCFMT_LEFT, 200, ColumnFlags::None);
	cm->AddColumn(L"Platform", LVCFMT_LEFT, 60, ColumnType::Platform, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"Description", LVCFMT_LEFT, 250, ColumnType::Description, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"Company Name", LVCFMT_LEFT, 150, ColumnType::CompanyName, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"DPI Awareness", LVCFMT_LEFT, 80, ColumnType::DPIAware, ColumnFlags::None);

	cm->UpdateColumns();

	auto count = m_pm.EnumProcesses();
	m_Items = m_pm.GetProcesses();
	m_spList->SetItemCount((int)count, 0);
	SetTimer(1, m_Interval);

	return 0;
}

LRESULT CProcessesView::OnTimer(UINT, WPARAM, LPARAM, BOOL&) {
	if (m_Processing)
		return 0;

	m_Processing = true;
	::TrySubmitThreadpoolCallback([](auto, auto param) {
		auto p = (CProcessesView*)param;
		p->UpdateProcesses();
		}, this, nullptr);

	return 0;
}

void CProcessesView::DoSort(const SortInfo* si) {
	if (m_Processing)
		// wait until update is complete
		return;

	auto col = si->SortColumn;
	auto asc = si->SortAscending;

	std::sort(m_Items.begin(), m_Items.end(), [&](const auto& p1, const auto& p2) {
		switch (GetColumnManager(m_List)->GetColumnTag<ColumnType>(col)) {
			case ColumnType::Name: return SortHelper::Sort(p1->GetImageName(), p2->GetImageName(), asc);
			case ColumnType::PackageName: return SortHelper::Sort(p1->GetPackageFullName(), p2->GetPackageFullName(), asc);
			case ColumnType::Id: return SortHelper::Sort(p1->Id, p2->Id, asc);
			case ColumnType::UserName: return SortHelper::Sort(p1->GetUserName(), p2->GetUserName(), asc);
			case ColumnType::Session: return SortHelper::Sort(p1->SessionId, p2->SessionId, asc);
			case ColumnType::PriorityClass: return SortHelper::Sort(Helpers::PriorityClassToPriority(p1->GetPriorityClass()), Helpers::PriorityClassToPriority(p2->GetPriorityClass()), asc);
			case ColumnType::CPU: return SortHelper::Sort(p1->CPU, p2->CPU, asc);
			case ColumnType::Parent: return SortHelper::Sort(p1->ParentId, p2->ParentId, asc);
			case ColumnType::CreateTime: return SortHelper::Sort(p1->CreateTime, p2->CreateTime, asc);
			case ColumnType::Commit: return SortHelper::Sort(p1->PagefileUsage, p2->PagefileUsage, asc);
			case ColumnType::PeakCommit: return SortHelper::Sort(p1->PeakPagefileUsage, p2->PeakPagefileUsage, asc);
			case ColumnType::BasePriority: return SortHelper::Sort(p1->BasePriority, p2->BasePriority, asc);
			case ColumnType::Threads: return SortHelper::Sort(p1->ThreadCount, p2->ThreadCount, asc);
			case ColumnType::Handles: return SortHelper::Sort(p1->HandleCount, p2->HandleCount, asc);
			case ColumnType::WorkingSet: return SortHelper::Sort(p1->WorkingSetSize, p2->WorkingSetSize, asc);
			case ColumnType::ImagePath: return SortHelper::Sort(p1->GetFullImagePath(), p2->GetFullImagePath(), asc);
			case ColumnType::CPUTime: return SortHelper::Sort(p1->KernelTime + p1->UserTime, p2->KernelTime + p2->UserTime, asc);
			case ColumnType::PeakThreads: return SortHelper::Sort(p1->PeakThreads, p2->PeakThreads, asc);
			case ColumnType::VirtualSize: return SortHelper::Sort(p1->VirtualSize, p2->VirtualSize, asc);
			case ColumnType::PeakWorkingSet: return SortHelper::Sort(p1->PeakWorkingSetSize, p2->PeakWorkingSetSize, asc);
			//case ColumnType::Attributes: return SortHelper::Sort(p1->GetAttributes(m_pm), p2->GetAttributes(m_pm), asc);
			case ColumnType::PagedPool: return SortHelper::Sort(p1->PagedPoolUsage, p2->PagedPoolUsage, asc);
			case ColumnType::PeakPagedPool: return SortHelper::Sort(p1->PeakPagedPoolUsage, p2->PeakPagedPoolUsage, asc);
			case ColumnType::NonPagedPool: return SortHelper::Sort(p1->NonPagedPoolUsage, p2->NonPagedPoolUsage, asc);
			case ColumnType::PeakNonPagedPool: return SortHelper::Sort(p1->PeakNonPagedPoolUsage, p2->PeakNonPagedPoolUsage, asc);
			//case ColumnType::MemoryPriority: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetMemoryPriority(), GetProcessInfoEx(p2.get()).GetMemoryPriority(), asc);
			//case ColumnType::IoPriority: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetIoPriority(), GetProcessInfoEx(p2.get()).GetIoPriority(), asc);
			//case ColumnType::CommandLine: return SortHelper::Sort(p1->GetCommandLine(), p2->GetCommandLine(), asc);
			case ColumnType::ReadBytes: return SortHelper::Sort(p1->ReadTransferCount, p2->ReadTransferCount, asc);
			case ColumnType::WriteBytes: return SortHelper::Sort(p1->WriteTransferCount, p2->WriteTransferCount, asc);
			case ColumnType::OtherBytes: return SortHelper::Sort(p1->OtherTransferCount, p2->OtherTransferCount, asc);
			case ColumnType::ReadCount: return SortHelper::Sort(p1->ReadOperationCount, p2->ReadOperationCount, asc);
			case ColumnType::WriteCount: return SortHelper::Sort(p1->WriteOperationCount, p2->WriteOperationCount, asc);
			case ColumnType::OtherCount: return SortHelper::Sort(p1->OtherOperationCount, p2->OtherOperationCount, asc);
			//case ColumnType::GDIObjects: return SortHelper::Sort(p1->GetGdiObjects(), p2->GetGdiObjects(), asc);
			//case ColumnType::UserObjects: return SortHelper::Sort(p1->GetUserObjects(), p2->GetUserObjects(), asc);
			//case ColumnType::PeakGdiObjects: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetPeakGdiObjects(), GetProcessInfoEx(p2.get()).GetPeakGdiObjects(), asc);
			//case ColumnType::PeakUserObjects: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetPeakUserObjects(), GetProcessInfoEx(p2.get()).GetPeakUserObjects(), asc);
			case ColumnType::KernelTime: return SortHelper::Sort(p1->KernelTime, p2->KernelTime, asc);
			case ColumnType::UserTime: return SortHelper::Sort(p1->UserTime, p2->UserTime, asc);
			case ColumnType::Elevated: return SortHelper::Sort(p1->IsElevated(), p2->IsElevated(), asc);
			case ColumnType::Integrity: return SortHelper::Sort(p1->GetIntegrityLevel(), p2->GetIntegrityLevel(), asc);
			//case ColumnType::Virtualized: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetVirtualizationState(), GetProcessInfoEx(p2.get()).GetVirtualizationState(), asc);
			case ColumnType::JobId: return SortHelper::Sort(p1->JobObjectId, p2->JobObjectId, asc);
			//case ColumnType::WindowTitle: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetWindowTitle(), GetProcessInfoEx(p2.get()).GetWindowTitle(), asc);
			case ColumnType::Platform: return SortHelper::Sort(p1->GetPlatform(), p2->GetPlatform(), asc);
			//case ColumnType::Description: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetDescription(), GetProcessInfoEx(p2.get()).GetDescription(), asc);
			//case ColumnType::Company: return SortHelper::Sort(GetProcessInfoEx(p1.get()).GetCompanyName(), GetProcessInfoEx(p2.get()).GetCompanyName(), asc);
			//case ColumnType::DPIAware: return SortHelper::Sort(p1->GetDpiAwareness(), p2->GetDpiAwareness(), asc);
		}
		return false;
		});

}

LRESULT CProcessesView::OnContinueProcessing(UINT, WPARAM, LPARAM, BOOL&) {
	auto tick = GetTickCount64();
	for (auto& p : m_pm.GetNewProcesses()) {
		p->Flags = ProcessFlags::New;
		p->TargetTime = tick + 2000;
		m_Items.push_back(p);
	}
	for (auto& p : m_pm.GetTerminatedProcesses()) {
		p->Flags = ProcessFlags::Terminated;
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
	m_Processing = false;
	m_spList->SetItemCount((int)m_Items.size(), LVSICF_NOSCROLL | LVSICF_NOINVALIDATEALL);
	auto si = GetSortInfo(m_List);
	if (si)
		Sort(si);

	m_spList->RedrawItems(m_spList->GetTopIndex(), m_spList->GetTopIndex() + m_spList->GetCountPerPage());
	return 0;
}

CString CProcessesView::GetTitle() const {
	return L"Processes";
}

CString CProcessesView::GetColumnText(HWND h, int row, int col) {
	auto& p = m_Items[row];
	switch (GetColumnManager(h)->GetColumnTag<ColumnType>(col)) {
		case ColumnType::Name: return p->GetImageName().c_str();
		case ColumnType::Id: return std::format("{}", p->Id).c_str();
		case ColumnType::CPU: 
			return p->CPU > 0 && (p->Flags & ProcessFlags::Terminated) == ProcessFlags::None ? std::format(L"{:6.2f}", p->CPU / 10000.0f).c_str() : L"";

		case ColumnType::Handles: return std::format("{}", p->HandleCount).c_str();
		case ColumnType::Threads: return std::format("{}", p->ThreadCount).c_str();
		case ColumnType::PeakThreads: return std::format("{}", p->PeakThreads).c_str();
		case ColumnType::ImagePath: return p->GetFullImagePath();
		case ColumnType::PackageName: return p->GetPackageFullName().c_str();
		case ColumnType::PriorityClass: return StringHelper::PriorityClassToString(p->GetPriorityClass());
		case ColumnType::CreateTime: return StringHelper::TimeToString(p->CreateTime, true);
		case ColumnType::Session: return std::format(L"{}", p->SessionId).c_str();
		case ColumnType::BasePriority: return std::format(L"{}", p->BasePriority).c_str();
		case ColumnType::Commit: return StringHelper::FormatSize(p->PagefileUsage >> 10);
		case ColumnType::WorkingSet: return StringHelper::FormatSize(p->WorkingSetSize >> 10);
		case ColumnType::PrivateWorkingSet: return StringHelper::FormatSize(p->WorkingSetPrivateSize >> 10);
		case ColumnType::VirtualSize: return StringHelper::FormatSize(p->VirtualSize >> 10);
		case ColumnType::PeakVirtualSize: return StringHelper::FormatSize(p->PeakVirtualSize >> 10);
		case ColumnType::PagedPool: return StringHelper::FormatSize(p->PagedPoolUsage >> 10);
		case ColumnType::PeakPagedPool: return StringHelper::FormatSize(p->PeakPagedPoolUsage >> 10);
		case ColumnType::NonPagedPool: return StringHelper::FormatSize(p->NonPagedPoolUsage >> 10);
		case ColumnType::PeakNonPagedPool: return StringHelper::FormatSize(p->PeakNonPagedPoolUsage >> 10);
		case ColumnType::CommandLine: return p->GetCommandLine();
		case ColumnType::UserName: return p->GetUserName();
		case ColumnType::KernelTime: return StringHelper::TimeSpanToString(p->KernelTime);
		case ColumnType::UserTime: return StringHelper::TimeSpanToString(p->UserTime);
		case ColumnType::CPUTime: return StringHelper::TimeSpanToString(p->KernelTime + p->UserTime);
		case ColumnType::Integrity: return StringHelper::IntegrityLevelToString(p->GetIntegrityLevel());
		case ColumnType::Platform: return std::format("{} bit", p->GetPlatform()).c_str();
		case ColumnType::Virtualization: return StringHelper::VirtualizationStateToString(p->GetVirtualizationState());
		case ColumnType::Elevated: return p->IsElevated() ? L"Yes" : L"No";
		case ColumnType::Description: return p->GetDesciption();
		case ColumnType::CompanyName: return p->GetCompanyName();
	}
	return L"";
}

int CProcessesView::GetRowImage(HWND, int row, int col) const {
	if (row >= m_Items.size())
		return -1;

	auto& p = m_Items[row];
	if (p->Image < 0) {
		p->Image = 0;
		Process process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p->Id));
		if (process) {
			auto path = process.GetFullImageName();
			if(!path.empty())
				p->Image = ImageIconCache::Get().GetIcon(path);
		}
	}
	return p->Image;
}

void CProcessesView::UpdateProcesses() {
	//
	// called on a thread pool thread
	//
	m_pm.EnumProcesses();
	SendMessage(WM_CONTINUE_PROCESSING);
}

DWORD CProcessesView::OnPrePaint(int, LPNMCUSTOMDRAW cd) {
	return CDRF_NOTIFYITEMDRAW;
}

DWORD CProcessesView::OnItemPrePaint(int, LPNMCUSTOMDRAW cd) {
	auto lv = (NMLVCUSTOMDRAW*)cd;
	lv->clrTextBk = CLR_INVALID;
	int row = (int)cd->dwItemSpec;
	ATLASSERT(row < m_Items.size());

	auto& p = m_Items[row];
	auto tick = GetTickCount64();
	if ((p->Flags & ProcessFlags::Terminated) == ProcessFlags::Terminated) {
		lv->clrTextBk = RGB(255, 64, 0);
		if (tick >= p->TargetTime) {
			m_Deleted.insert(row);
		}
	}
	else if ((p->Flags & ProcessFlags::New) == ProcessFlags::New) {
		lv->clrTextBk = ThemeHelper::IsDefault() ? RGB(0, 255, 64) : RGB(0, 160, 64);
		if (tick >= p->TargetTime)
			p->Flags &= ~ProcessFlags::New;
	}
	return CDRF_SKIPPOSTPAINT;
}
