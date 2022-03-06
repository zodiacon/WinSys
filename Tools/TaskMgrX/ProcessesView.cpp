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
#include "SelectColumnsDlg.h"
#include "ColorHelper.h"
#include "StandardColors.h"

#pragma comment(lib, "Version.lib")

using namespace WinSys;

BOOL CProcessesView::PreTranslateMessage(MSG* pMsg) {
	pMsg;
	return FALSE;
}

void CProcessesView::OnFinalMessage(HWND /*hWnd*/) {
	delete this;
}

LRESULT CProcessesView::OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	ToolBarButtonInfo buttons[] = {
		{ ID_PROCESS_KILL, IDI_DELETE, 0, L"Kill" },
		{ 0 },
		{ ID_PROCESS_COLUMNS, IDI_COLUMNS, 0, L"Columns" },
		{ 0 },
		{ ID_PROCESS_COLORS, IDI_COLORS, 0, L"Colors" },
	};
	CreateAndInitToolBar(buttons, _countof(buttons));

	m_hWndClient = m_List.Create(m_hWnd, rcDefault, nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS |
		LVS_OWNERDATA | LVS_SINGLESEL | LVS_REPORT | LVS_SHOWSELALWAYS, WS_EX_CLIENTEDGE);
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
	cm->AddColumn(L"Performance\\Base Priority", LVCFMT_RIGHT, 80, ColumnType::BasePriority, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Priority Class", LVCFMT_LEFT, 120, ColumnType::PriorityClass, ColumnFlags::Visible);
	cm->AddColumn(L"Performance\\Threads", LVCFMT_RIGHT, 60, ColumnType::Threads, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Peak Threads", LVCFMT_RIGHT, 60, ColumnType::PeakThreads, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Handles", LVCFMT_RIGHT, 70, ColumnType::Handles, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Attributes", LVCFMT_LEFT, 100, ColumnType::Attributes, ColumnFlags::Visible | ColumnFlags::Const);
	cm->AddColumn(L"Protection", LVCFMT_LEFT, 100, ColumnType::Protection, ColumnFlags::Const);
	cm->AddColumn(L"Image Path", LVCFMT_LEFT, 300, ColumnType::ImagePath, ColumnFlags::Const);
	cm->AddColumn(L"Create Time", LVCFMT_LEFT, 160, ColumnType::CreateTime, ColumnFlags::Visible | ColumnFlags::Numeric | ColumnFlags::Const);
	cm->AddColumn(L"Memory\\Commit (K)", LVCFMT_RIGHT, 110, ColumnType::Commit, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak Commit (K)", LVCFMT_RIGHT, 120, ColumnType::PeakCommit, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Working Set (K)", LVCFMT_RIGHT, 110, ColumnType::WorkingSet, ColumnFlags::Visible | ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak WS (K)", LVCFMT_RIGHT, 120, ColumnType::PeakWorkingSet, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Virtual Size (K)", LVCFMT_RIGHT, 110, ColumnType::VirtualSize, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak Virtual Size (K)", LVCFMT_RIGHT, 120, ColumnType::PeakVirtualSize, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Paged Pool (K)", LVCFMT_RIGHT, 110, ColumnType::PagedPool, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak Paged (K)", LVCFMT_RIGHT, 110, ColumnType::PeakPagedPool, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Non Paged (K)", LVCFMT_RIGHT, 110, ColumnType::NonPagedPool, ColumnFlags::Numeric);
	cm->AddColumn(L"Memory\\Peak NPaged (K)", LVCFMT_RIGHT, 120, ColumnType::PeakNonPagedPool, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\Kernel Time", LVCFMT_RIGHT, 120, ColumnType::KernelTime, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\User Time", LVCFMT_RIGHT, 120, ColumnType::UserTime, ColumnFlags::Numeric);
	cm->AddColumn(L"Performance\\I/O Priority", LVCFMT_LEFT, 80, ColumnType::IoPriority, ColumnFlags::None);
	cm->AddColumn(L"Performance\\Memory Priority", LVCFMT_RIGHT, 80, ColumnType::MemoryPriority, ColumnFlags::Numeric);
	cm->AddColumn(L"Command Line", LVCFMT_LEFT, 250, ColumnType::CommandLine, ColumnFlags::Const);
	cm->AddColumn(L"Package Name", LVCFMT_LEFT, 250, ColumnType::PackageName, ColumnFlags::Const);
	cm->AddColumn(L"Job Object Id", LVCFMT_RIGHT, 100, ColumnType::JobId, ColumnFlags::Numeric | ColumnFlags::Const);
	cm->AddColumn(L"I/O\\I/O Read Bytes", LVCFMT_RIGHT, 120, ColumnType::ReadBytes, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Write Bytes", LVCFMT_RIGHT, 120, ColumnType::WriteBytes, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Other Bytes", LVCFMT_RIGHT, 120, ColumnType::OtherBytes, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Reads", LVCFMT_RIGHT, 90, ColumnType::ReadCount, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Writes", LVCFMT_RIGHT, 90, ColumnType::WriteCount, ColumnFlags::Numeric);
	cm->AddColumn(L"I/O\\I/O Other", LVCFMT_RIGHT, 90, ColumnType::OtherCount, ColumnFlags::Numeric);
	cm->AddColumn(L"GUI\\GDI Objects", LVCFMT_RIGHT, 90, ColumnType::GDIObjects, ColumnFlags::Numeric);
	cm->AddColumn(L"GUI\\User Objects", LVCFMT_RIGHT, 90, ColumnType::UserObjects, ColumnFlags::Numeric);
	cm->AddColumn(L"GUI\\Peak GDI Objects", LVCFMT_RIGHT, 90, ColumnType::PeakGDIObjects, ColumnFlags::Numeric);
	cm->AddColumn(L"GUI\\Peak User Objects", LVCFMT_RIGHT, 90, ColumnType::PeakUserObjects, ColumnFlags::Numeric);
	cm->AddColumn(L"Token\\Integrity", LVCFMT_LEFT, 70, ColumnType::Integrity, ColumnFlags::Visible);
	cm->AddColumn(L"Token\\Elevated", LVCFMT_LEFT, 60, ColumnType::Elevated, ColumnFlags::Const);
	cm->AddColumn(L"Token\\Virtualization", LVCFMT_LEFT, 85, ColumnType::Virtualization, ColumnFlags::None);
	cm->AddColumn(L"Window Title", LVCFMT_LEFT, 200, ColumnType::WindowTitle, ColumnFlags::None);
	cm->AddColumn(L"Platform", LVCFMT_LEFT, 60, ColumnType::Platform, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"Description", LVCFMT_LEFT, 250, ColumnType::Description, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"Company Name", LVCFMT_LEFT, 150, ColumnType::CompanyName, ColumnFlags::Const | ColumnFlags::Visible);
	cm->AddColumn(L"DPI Awareness", LVCFMT_LEFT, 80, ColumnType::DPIAware, ColumnFlags::None);

	cm->UpdateColumns();

	UpdateLocalUI();
	m_Terminated.reserve(16);
	m_New.reserve(16);
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
	auto tick = GetTickCount64();
	auto selected = m_spList->GetSelectedIndex();
	if (selected >= 0)
		m_SelectedProcess = m_Items[selected];
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
			case ColumnType::Attributes: return SortHelper::Sort(p1->GetAttributes(m_pm), p2->GetAttributes(m_pm), asc);
			case ColumnType::PagedPool: return SortHelper::Sort(p1->PagedPoolUsage, p2->PagedPoolUsage, asc);
			case ColumnType::PeakPagedPool: return SortHelper::Sort(p1->PeakPagedPoolUsage, p2->PeakPagedPoolUsage, asc);
			case ColumnType::NonPagedPool: return SortHelper::Sort(p1->NonPagedPoolUsage, p2->NonPagedPoolUsage, asc);
			case ColumnType::PeakNonPagedPool: return SortHelper::Sort(p1->PeakNonPagedPoolUsage, p2->PeakNonPagedPoolUsage, asc);
			case ColumnType::MemoryPriority: return SortHelper::Sort(p1->GetMemoryPriority(), p2->GetMemoryPriority(), asc);
			case ColumnType::IoPriority: return SortHelper::Sort(p1->GetIoPriority(), p2->GetIoPriority(), asc);
			case ColumnType::CommandLine: return SortHelper::Sort(p1->GetCommandLine(), p2->GetCommandLine(), asc);
			case ColumnType::ReadBytes: return SortHelper::Sort(p1->ReadTransferCount, p2->ReadTransferCount, asc);
			case ColumnType::WriteBytes: return SortHelper::Sort(p1->WriteTransferCount, p2->WriteTransferCount, asc);
			case ColumnType::OtherBytes: return SortHelper::Sort(p1->OtherTransferCount, p2->OtherTransferCount, asc);
			case ColumnType::ReadCount: return SortHelper::Sort(p1->ReadOperationCount, p2->ReadOperationCount, asc);
			case ColumnType::WriteCount: return SortHelper::Sort(p1->WriteOperationCount, p2->WriteOperationCount, asc);
			case ColumnType::OtherCount: return SortHelper::Sort(p1->OtherOperationCount, p2->OtherOperationCount, asc);
			case ColumnType::GDIObjects: return SortHelper::Sort(p1->GetGdiObjects(), p2->GetGdiObjects(), asc);
			case ColumnType::UserObjects: return SortHelper::Sort(p1->GetUserObjects(), p2->GetUserObjects(), asc);
			case ColumnType::PeakGDIObjects: return SortHelper::Sort(p1->GetPeakGdiObjects(), p2->GetPeakGdiObjects(), asc);
			case ColumnType::PeakUserObjects: return SortHelper::Sort(p1->GetPeakUserObjects(), p2->GetPeakUserObjects(), asc);
			case ColumnType::KernelTime: return SortHelper::Sort(p1->KernelTime, p2->KernelTime, asc);
			case ColumnType::UserTime: return SortHelper::Sort(p1->UserTime, p2->UserTime, asc);
			case ColumnType::Elevated: return SortHelper::Sort(p1->IsElevated(), p2->IsElevated(), asc);
			case ColumnType::Integrity: return SortHelper::Sort(p1->GetIntegrityLevel(), p2->GetIntegrityLevel(), asc);
			case ColumnType::Virtualization: return SortHelper::Sort(p1->GetVirtualizationState(), p2->GetVirtualizationState(), asc);
			case ColumnType::JobId: return SortHelper::Sort(p1->JobObjectId, p2->JobObjectId, asc);
			case ColumnType::WindowTitle: return SortHelper::Sort(p1->GetWindowTitle(), p2->GetWindowTitle(), asc);
			case ColumnType::Platform: return SortHelper::Sort(p1->GetPlatform(), p2->GetPlatform(), asc);
			case ColumnType::Description: return SortHelper::Sort(p1->GetDescription(), p2->GetDescription(), asc);
			case ColumnType::CompanyName: return SortHelper::Sort(p1->GetCompanyName(), p2->GetCompanyName(), asc);
			case ColumnType::Protection: return SortHelper::Sort(p1->GetProtection().Level, p2->GetProtection().Level, asc);
			case ColumnType::DPIAware: return SortHelper::Sort(p1->GetDpiAwareness(), p2->GetDpiAwareness(), asc);
		}
		return false;
		});

}

void CProcessesView::PreSort(HWND) {
	if(m_SelectedProcess == nullptr)
		m_SelectedProcess = m_spList->GetSelectedIndex() < 0 ? nullptr : m_Items[m_spList->GetSelectedIndex()];
}

LRESULT CProcessesView::OnContinueProcessing(UINT, WPARAM, LPARAM, BOOL&) {
	m_Processing = false;
	m_spList->SetItemCount((int)m_Items.size(), LVSICF_NOSCROLL | LVSICF_NOINVALIDATEALL);
	auto si = GetSortInfo(m_List);
	if (si)
		Sort(si);

	m_spList->RedrawItems(m_spList->GetTopIndex(), m_spList->GetTopIndex() + m_spList->GetCountPerPage());
	return 0;
}

LRESULT CProcessesView::OnKillProcess(WORD, WORD, HWND, BOOL&) {
	int selected = m_spList->GetSelectedIndex();
	ATLASSERT(selected >= 0);
	auto& p = m_Items[selected];

	CString text;
	text.Format(L"Kill process %u (%ws)?", p->Id, p->GetImageName().c_str());
	if (AtlMessageBox(*this, (PCWSTR)text, IDS_TITLE, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON2) == IDCANCEL)
		return 0;

	Process process;
	bool ok = false;
	if (process.Open(p->Id, ProcessAccessMask::Terminate)) {
		ok = process.Terminate(0);
	}
	if (!ok)
		AtlMessageBox(*this, L"Failed to kill process", IDS_TITLE, MB_ICONERROR);

	return 0;
}

LRESULT CProcessesView::OnItemChanged(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/) {
	UpdateLocalUI();
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
			if (p->IsSuspended())
				return L"Suspended";
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
		case ColumnType::PeakWorkingSet: return StringHelper::FormatSize(p->PeakWorkingSetSize >> 10);
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
		case ColumnType::Platform: return std::format(L"{} bit", p->GetPlatform()).c_str();
		case ColumnType::Virtualization: return StringHelper::VirtualizationStateToString(p->GetVirtualizationState());
		case ColumnType::Elevated: return p->IsElevated() ? L"Yes" : L"No";
		case ColumnType::Description: return p->GetDescription();
		case ColumnType::CompanyName: return p->GetCompanyName();
		case ColumnType::MemoryPriority: return p->GetMemoryPriority() < 0 ? L"" : std::format(L"{}", p->GetMemoryPriority()).c_str();
		case ColumnType::JobId: return p->JobObjectId == 0 ? L"" : std::format(L"{}", p->JobObjectId).c_str();
		case ColumnType::ReadBytes: return StringHelper::FormatSize(p->ReadTransferCount);
		case ColumnType::WriteBytes: return StringHelper::FormatSize(p->WriteTransferCount);
		case ColumnType::OtherBytes: return StringHelper::FormatSize(p->OtherTransferCount);
		case ColumnType::ReadCount: return StringHelper::FormatSize(p->ReadOperationCount);
		case ColumnType::WriteCount: return StringHelper::FormatSize(p->WriteOperationCount);
		case ColumnType::OtherCount: return StringHelper::FormatSize(p->OtherOperationCount);
		case ColumnType::GDIObjects: return std::format(L"{}", p->GetGdiObjects()).c_str();
		case ColumnType::PeakGDIObjects: return std::format(L"{}", p->GetPeakGdiObjects()).c_str();
		case ColumnType::UserObjects: return std::format(L"{}", p->GetUserObjects()).c_str();
		case ColumnType::PeakUserObjects: return std::format(L"{}", p->GetPeakUserObjects()).c_str();
		case ColumnType::Parent: return std::format(L"{} ({})", p->GetParentImageName(m_pm, L"<Dead>"), p->ParentId).c_str();
		case ColumnType::Attributes: return StringHelper::ProcessAttributesToString(p->GetAttributes(m_pm));
		case ColumnType::Protection: return StringHelper::ProcessProtectionToString(p->GetProtection());
		case ColumnType::IoPriority: return StringHelper::IoPriorityToString(p->GetIoPriority());
		case ColumnType::WindowTitle: return p->GetWindowTitle();
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
			if (!path.empty())
				p->Image = ImageIconCache::Get().GetIcon(path);
		}
	}
	return p->Image;
}

COLORREF CProcessesView::GetProcessColor(ProcessInfoEx* p) const {
	if (p->IsSuspended())
		return RGB(128, 128, 128);

	auto attr = p->GetAttributes(m_pm);
	auto color = CLR_INVALID;
	if ((attr & ProcessAttributes::Secure) == ProcessAttributes::Secure)
		color = StandardColors::PaleVioletRed;
	else if ((attr & ProcessAttributes::Immersive) == ProcessAttributes::Immersive)
		color = StandardColors::Cyan;
	else if ((attr & ProcessAttributes::Protected) == ProcessAttributes::Protected)
		color = StandardColors::Fuchsia;
	else if ((attr & ProcessAttributes::Service) == ProcessAttributes::Service)
		color = StandardColors::Pink;
	else if ((attr & ProcessAttributes::Managed) == ProcessAttributes::Managed)
		color = ColorHelper::Darken(StandardColors::Yellow, 20);
	else if ((attr & ProcessAttributes::Pico) == ProcessAttributes::Pico)
		color = StandardColors::LightGoldenrodYellow;
	else if ((attr & ProcessAttributes::Wow64) == ProcessAttributes::Wow64)
		color = StandardColors::LightBlue;
	else if ((attr & ProcessAttributes::InJob) == ProcessAttributes::InJob)
		color = ColorHelper::Lighten(StandardColors::SaddleBrown, 20);

	if (color != CLR_INVALID && !ThemeHelper::IsDefault())
		color = ColorHelper::Darken(color, 20);

	return color;
}

void CProcessesView::UpdateProcesses() {
	//
	// called on a thread pool thread
	//
	m_pm.EnumProcesses();

	auto tick = ::GetTickCount64();
	int count = (int)m_Terminated.size();
	for (int i = 0; i < count; i++) {
		auto& p = m_Terminated[i];
		if (p->TargetTime < tick) {
			m_Items.erase(std::find(m_Items.begin(), m_Items.end(), p));
			m_Terminated.erase(m_Terminated.begin() + i);
			i--;
			count--;
		}
	}

	count = (int)m_New.size();
	for (int i = 0; i < count; i++) {
		auto& p = m_New[i];
		if (p->TargetTime < tick) {
			p->Flags &= ~ProcessFlags::New;
			m_New.erase(m_New.begin() + i);
			i--;
			count--;
		}
	}

	for (auto& p : m_pm.GetNewProcesses()) {
		p->Flags = ProcessFlags::New;
		p->TargetTime = tick + 2000;
		m_Items.push_back(p);
		m_New.push_back(p);
	}
	for (auto& p : m_pm.GetTerminatedProcesses()) {
		p->Flags = ProcessFlags::Terminated;
		p->TargetTime = tick + 2000;
		m_Terminated.push_back(p);
	}

	SendMessage(WM_CONTINUE_PROCESSING);
}

void CProcessesView::UpdateLocalUI() {
	auto selected = m_spList->GetSelectedCount();
	UIEnable(ID_PROCESS_KILL, selected == 1);
}

DWORD CProcessesView::OnPrePaint(int, LPNMCUSTOMDRAW cd) {
	if (cd->hdr.hwndFrom != m_List) {
		SetMsgHandled(FALSE);
		return CDRF_DODEFAULT;
	}
	return CDRF_NOTIFYITEMDRAW;
}

void CProcessesView::PostSort(HWND) {
	if (m_SelectedProcess) {
		int count = (int)m_Items.size();
		for(int i = 0; i < count; i++)
			if (m_SelectedProcess == m_Items[i]) {
				m_spList->SetItemState(i, -1, LVIS_SELECTED, LVIS_SELECTED);
				break;
			}
		m_SelectedProcess = nullptr;
	}
}

DWORD CProcessesView::OnSubItemPrePaint(int, LPNMCUSTOMDRAW cd) {
	return CDRF_SKIPPOSTPAINT;
}

DWORD CProcessesView::OnItemPrePaint(int, LPNMCUSTOMDRAW cd) {
	if (cd->hdr.hwndFrom != m_List) {
		SetMsgHandled(FALSE);
		return CDRF_DODEFAULT;
	}
	auto lv = (NMLVCUSTOMDRAW*)cd;
	lv->clrTextBk = CLR_INVALID;
	int row = (int)cd->dwItemSpec;
	ATLASSERT(row < m_Items.size());

	if (m_spList->GetItemState(row, LVIS_SELECTED) == LVIS_SELECTED) {
		// skip selected items
	}
	else {
		auto& p = m_Items[row];
		auto tick = GetTickCount64();
		if ((p->Flags & ProcessFlags::Terminated) == ProcessFlags::Terminated) {
			lv->clrTextBk = RGB(255, 64, 0);
		}
		else if ((p->Flags & ProcessFlags::New) == ProcessFlags::New) {
			lv->clrTextBk = ThemeHelper::IsDefault() ? RGB(0, 255, 64) : RGB(0, 160, 64);
		}
		else {
			lv->clrTextBk = GetProcessColor(p.get());
		}
	}
	return CDRF_SKIPPOSTPAINT | CDRF_NOTIFYSUBITEMDRAW;
}

bool CProcessesView::OnRightClickHeader(HWND, int index, CPoint const& pt) {
	CMenu menu;
	menu.LoadMenu(IDR_CONTEXT);
	m_SelectedHeader = index;
	auto cmd = GetFrame()->TrackPopupMenu(menu.GetSubMenu(1), TPM_RETURNCMD, pt.x, pt.y);
	if (cmd) {
		LRESULT result;
		return ProcessWindowMessage(m_hWnd, WM_COMMAND, cmd, 0, result, 0);
	}
	return false;
}

LRESULT CProcessesView::OnSelectColumns(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	CSelectColumnsDlg dlg(GetColumnManager(m_List));
	dlg.DoModal();
	m_spList->RedrawItems(m_spList->GetTopIndex(), m_spList->GetTopIndex() + m_spList->GetCountPerPage());
	return 0;
}

bool CProcessesView::OnRightClickList(HWND, int row, int col, CPoint const& pt) {
	KillTimer(1);
	CMenu menu;
	menu.LoadMenu(IDR_CONTEXT);
	auto cmd = GetFrame()->TrackPopupMenu(menu.GetSubMenu(0), TPM_RETURNCMD, pt.x, pt.y);
	if (m_Running)
		SetTimer(1, m_Interval);
	if (cmd) {
		LRESULT result;
		return ProcessWindowMessage(m_hWnd, WM_COMMAND, cmd, 0, result, 0);
	}
	return false;
}

LRESULT CProcessesView::OnHideColumn(WORD, WORD, HWND, BOOL&) {
	ATLASSERT(m_SelectedHeader >= 0);
	auto cm = GetColumnManager(m_List);
	cm->SetVisible(cm->GetRealColumn(m_SelectedHeader), false);
	cm->UpdateColumns();
	m_List.RedrawItems(m_spList->GetTopIndex(), m_spList->GetTopIndex() + m_spList->GetCountPerPage());

	return 0;
}
