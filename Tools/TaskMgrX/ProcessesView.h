// View.h : interface of the CView class
//
/////////////////////////////////////////////////////////////////////////////

#pragma once

#include "ViewBase.h"
#include "VirtualListView.h"
#include "ProcessInfo.h"
#include <set>
#include "IListView.h"
#include <ProcessManager.h>
#include "ProcessInfoEx.h"

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
	CString GetColumnText(HWND, int row, int col);
	int GetRowImage(HWND, int row, int) const;
	void DoSort(SortInfo const* si);

	DWORD OnPrePaint(int, LPNMCUSTOMDRAW cd);
	DWORD OnItemPrePaint(int, LPNMCUSTOMDRAW cd);

protected:
	const UINT WM_CONTINUE_PROCESSING = WM_APP + 100;

	BEGIN_MSG_MAP(CProcessesView)
		MESSAGE_HANDLER(WM_CONTINUE_PROCESSING, OnContinueProcessing)
		MESSAGE_HANDLER(WM_TIMER, OnTimer)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		CHAIN_MSG_MAP(CCustomDraw<CProcessesView>)
		CHAIN_MSG_MAP(CVirtualListView<CProcessesView>)
		CHAIN_MSG_MAP(CViewBase)
	END_MSG_MAP()

private:
	void UpdateProcesses();

	enum class ColumnType {
		Name, Id, Threads, Handles, Session, UserName, CPU, CPUTime, KernelTime, UserTime, Parent,
		PrivateBytes, WorkingSet, PeakWorkingSet, VirtualSize, PeakVirtualSize, PrivateWorkingSet, 
		PagedPool, PeakPagedPool, Commit, PeakCommit, NonPagedPool, PeakNonPagedPool,
		PeakThreads, CreateTime, Attributes, ImagePath, CommandLine, JobId, PackageName,
		BasePriority, PriorityClass, Platform, Description, CompanyName, DPIAware,
		ReadBytes, WriteBytes, OtherBytes, ReadCount, WriteCount, OtherCount,
		UserObjects, PeakUserObjects, GDIObjects, PeakGDIObjects,
		Integrity, Elevated, Virtualization, ExitTime,
		MemoryPriority, IoPriority, 
	};
	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnTimer(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnContinueProcessing(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);

	CListViewCtrl m_List;
	CComPtr<IListView> m_spList;
	ProcessManager<ProcessInfoEx> m_pm;
	std::vector<std::shared_ptr<ProcessInfoEx>> m_Items;
	std::set<int> m_Deleted;
	DWORD m_SelectedPid = -1;
	int m_Interval{ 1000 };
	bool m_Running{ true };
	bool m_Processing{ false };
};
