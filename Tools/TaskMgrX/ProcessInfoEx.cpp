#include "pch.h"
#include "ProcessInfoEx.h"
#include "Helpers.h"

using namespace WinSys;

CString const& ProcessInfoEx::GetFullImagePath() const {
	if (m_imagePath.IsEmpty())
		m_imagePath = Helpers::GetDosNameFromNtName(GetNativeImagePath().c_str()).c_str();
	return m_imagePath;
}

WinSys::ProcessPriorityClass ProcessInfoEx::GetPriorityClass() const {
	return OpenProcess() ? m_process.GetPriorityClass() : ProcessPriorityClass::Unknown;
}

int ProcessInfoEx::GetMemoryPriority() const {
	return OpenProcess() ? m_process.GetMemoryPriority() : -1;
}

CString const& ProcessInfoEx::GetCommandLine() const {
	if (m_commandLine.IsEmpty() && OpenProcess()) {
		m_commandLine = m_process.GetCommandLine().c_str();
	}
	return m_commandLine;
}

int ProcessInfoEx::GetPlatform() const {
	return OpenProcess() ? (m_process.IsWow64Process() ? 32 : 64) : 64;
}

VirtualizationState ProcessInfoEx::GetVirtualizationState() const {
	return OpenProcess() ? m_process.GetVirtualizationState() : VirtualizationState::Unknown;
}

bool ProcessInfoEx::IsElevated() const {
	return OpenProcess() ? m_process.IsElevated() : false;
}

DpiAwareness ProcessInfoEx::GetDpiAwareness() const {
	return OpenProcess() ? m_process.GetDpiAwareness() : DpiAwareness::Unknown;
}

IntegrityLevel ProcessInfoEx::GetIntegrityLevel() const {
	return OpenProcess() ? m_process.GetIntegrityLevel() : IntegrityLevel::Error;
}

bool ProcessInfoEx::OpenProcess() const {
	if (!m_process) {
		m_process.Open(Id, ProcessAccessMask::QueryInformation);
		if (!m_process)
			m_process.Open(Id, ProcessAccessMask::QueryLimitedInformation);
	}
	return m_process;
}

CString const& ProcessInfoEx::GetUserName() const {
	if (m_username.IsEmpty()) {
		if (Id <= 4)
			m_username = L"NT AUTHORITY\\SYSTEM";
		else {
			if (OpenProcess())
				m_username = m_process.GetUserName().c_str();
			if (m_username.IsEmpty())
				m_username = L"<access denied>";
		}
	}
	return m_username;
}

CString ProcessInfoEx::GetVersionObject(CString const& name) const {
	BYTE buffer[1 << 12];
	CString result;
	const auto& exe = GetFullImagePath();
	if (::GetFileVersionInfo(exe, 0, sizeof(buffer), buffer)) {
		WORD* langAndCodePage;
		UINT len;
		if (::VerQueryValue(buffer, L"\\VarFileInfo\\Translation", (void**)&langAndCodePage, &len)) {
			CString text;
			text.Format(L"\\StringFileInfo\\%04x%04x\\" + name, langAndCodePage[0], langAndCodePage[1]);
			WCHAR* desc;
			if (::VerQueryValue(buffer, text, (void**)&desc, &len))
				result = desc;
		}
	}
	return result;
}

ProcessProtection ProcessInfoEx::GetProtection() const {
	return OpenProcess() ? m_process.GetProtection() : ProcessProtection{};
}

WinSys::IoPriority ProcessInfoEx::GetIoPriority() const {
	return OpenProcess() ? m_process.GetIoPriority() : IoPriority::Unknown;
}

ULONG ProcessInfoEx::GetGdiObjects() const {
	return OpenProcess() ? m_process.GetGdiObjectCount() : 0;
}

ULONG ProcessInfoEx::GetPeakGdiObjects() const {
	return OpenProcess() ? m_process.GetPeakGdiObjectCount() : 0;
}

ULONG ProcessInfoEx::GetUserObjects() const {
	return OpenProcess() ? m_process.GetUserObjectCount() : 0;
}

std::wstring ProcessInfoEx::GetParentImageName(ProcessManager<ProcessInfoEx> const& pm, PCWSTR defaultText) const {
	if (ParentId > 0) {
		auto parent = pm.GetProcessById(ParentId);
		if (parent && (parent->CreateTime < CreateTime || parent->Id == 4)) {
			return parent->GetImageName();
		}
		return defaultText;
	}
	return L"";
}

ULONG ProcessInfoEx::GetPeakUserObjects() const {
	return OpenProcess() ? m_process.GetPeakUserObjectCount() : 0;
}

const CString& ProcessInfoEx::GetCompanyName() const {
	if (!m_companyDone) {
		m_company = GetVersionObject(L"CompanyName");
		m_companyDone = true;
	}
	return m_company;
}

bool ProcessInfoEx::IsSuspended() const {
	return OpenProcess() ? m_process.IsSuspended() : false;
}

const CString& ProcessInfoEx::GetDescription() const {
	if (!m_descriptionDone) {
		m_description = GetVersionObject(L"FileDescription");
		m_descriptionDone = true;
	}
	return m_description;
}

ProcessAttributes ProcessInfoEx::GetAttributes(ProcessManager<ProcessInfoEx> const& pm) const {
	if (!OpenProcess())
		return m_attributes;

	bool computed = (m_attributes & ProcessAttributes::Computed) == ProcessAttributes::Computed;
	if (!computed) {
		m_attributes = ProcessAttributes::None;
		if (m_process.IsPico())
			m_attributes |= ProcessAttributes::Pico;
		if (m_process.IsManaged())
			m_attributes |= ProcessAttributes::Managed;
		if (m_process.IsProtected())
			m_attributes |= ProcessAttributes::Protected;
		if (m_process.IsImmersive())
			m_attributes |= ProcessAttributes::Immersive;
		if (m_process.IsSecure())
			m_attributes |= ProcessAttributes::Secure;
		auto parent = pm.GetProcessById(ParentId);
		if (parent && ::_wcsicmp(parent->GetImageName().c_str(), L"services.exe") == 0)
			m_attributes |= ProcessAttributes::Service;
		if (m_process.IsWow64Process())
			m_attributes |= ProcessAttributes::Wow64;
		m_attributes |= ProcessAttributes::Computed;
	}
	if ((m_attributes & ProcessAttributes::InJob) == ProcessAttributes::None && m_process.IsInJob())
		m_attributes |= ProcessAttributes::InJob;
	return m_attributes;
}

CString ProcessInfoEx::GetWindowTitle() const {
	if (!OpenProcess())
		return L"";
	CString text;
	if (!m_hWnd) {
		if (m_firstThreadId == 0) {
			auto hThread = m_process.GetNextThread();
			if (hThread) {
				::EnumThreadWindows(::GetThreadId(hThread), [](auto hWnd, auto param) {
					if (::IsWindowVisible(hWnd)) {
						*(HWND*)param = hWnd;
						return FALSE;
					}
					return TRUE;
					}, (LPARAM)&m_hWnd);
				::CloseHandle(hThread);
			}
		}
	}
	if (m_hWnd) {
		::GetWindowText(m_hWnd, text.GetBufferSetLength(128), 128);
		text.FreeExtra();
	}
	return text;
}
