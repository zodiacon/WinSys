#pragma once

#include <ProcessInfo.h>
#include <Processes.h>
#include "ProcessManager.h"

enum class ProcessAttributes : DWORD {
	None =			0,
	InJob =			1 << 1,
	Managed =		1 << 2,
	Wow64 =			1 << 3,
	Protected =		1 << 4,
	Immersive =		1 << 5,
	Secure =		1 << 6,
	Suspended =		1 << 7,
	Service =		1 << 8,
	Pico =			1 << 9,
	Minimal =		1 << 10,
	NetCore =		1 << 11,
	Terminated =	1 << 12,
	Computed =		1 << 23,
};
DEFINE_ENUM_FLAG_OPERATORS(ProcessAttributes);

enum class ProcessFlags {
	None,
	New =				1 << 0,
	Terminated =		1 << 1,
};
DEFINE_ENUM_FLAG_OPERATORS(ProcessFlags);

struct ProcessInfoEx : ProcessInfo {
	ProcessFlags Flags{ ProcessFlags::None };
	int Image{ -1 };
	DWORD64 TargetTime;

	CString const& GetFullImagePath() const;
	PriorityClass GetPriorityClass() const;
	int GetMemoryPriority() const;
	IoPriorityHint GetIoPriority() const;
	CString const& GetCommandLine() const;
	CString const& GetUserName() const;
	IntegrityLevel GetIntegrityLevel() const;
	VirtualizationState GetVirtualizationState() const;
	DpiAwareness GetDpiAwareness() const;
	int GetPlatform() const;
	bool IsElevated() const;
	bool IsSuspended() const;
	CString const& GetCompanyName() const;
	CString const& GetDescription() const;
	ULONG GetGdiObjects() const;
	ULONG GetPeakGdiObjects() const;
	ULONG GetUserObjects() const;
	ULONG GetPeakUserObjects() const;
	std::wstring GetParentImageName(ProcessManager<ProcessInfoEx> const& pm, PCWSTR defaultText) const;
	ProcessAttributes GetAttributes(ProcessManager<ProcessInfoEx> const& pm) const;
	ProcessProtection GetProtection() const;
	CString GetWindowTitle() const;

private:
	CString GetVersionObject(CString const& name) const;
	bool OpenProcess() const;

	mutable CString m_imagePath, m_commandLine;
	mutable Process m_process;
	mutable CString m_username, m_company, m_description;
	mutable bool m_companyDone : 1 { false};
	mutable bool m_descriptionDone : 1 { false};
	mutable ProcessAttributes m_attributes{ ProcessAttributes::None };
	mutable HWND m_hWnd{ nullptr };
	mutable DWORD m_firstThreadId{ 0 };
};

