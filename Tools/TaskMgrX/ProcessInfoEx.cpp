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

CString const& ProcessInfoEx::GetCommandLine() const {
	if (m_commandLine.IsEmpty() && OpenProcess()) {
		m_commandLine = m_process.GetCommandLine().c_str();
	}
	return m_commandLine;
}

bool ProcessInfoEx::OpenProcess() const {
	if (!m_process) {
		m_process.Open(Id, ProcessAccessMask::QueryInformation);
		if (!m_process)
			m_process.Open(Id, ProcessAccessMask::QueryLimitedInformation);
	}
	return m_process;
}
