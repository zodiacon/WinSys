#include "pch.h"
#include "ProcessInfoEx.h"
#include "Helpers.h"

CString const& ProcessInfoEx::GetFullImagePath() const {
	if (m_imagePath.IsEmpty())
		m_imagePath = Helpers::GetDosNameFromNtName(GetNativeImagePath().c_str()).c_str();
	return m_imagePath;
}

PriorityClass ProcessInfoEx::GetPriorityClass() const {
	return OpenProcess() ? m_process.GetPriorityClass() : PriorityClass::Unknown;
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

CString ProcessInfoEx::GetVersionObject(const CString& name) const {
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

const CString& ProcessInfoEx::GetDescription() const {
	if (!m_descriptionDone) {
		m_description = GetVersionObject(L"FileDescription");
		m_descriptionDone = true;
	}
	return m_description;
}
