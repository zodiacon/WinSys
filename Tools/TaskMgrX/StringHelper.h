#pragma once

#include <processes.h>
#include "ProcessInfoEx.h"

struct StringHelper abstract final {
	static PCWSTR PriorityClassToString(WinSys::ProcessPriorityClass pc);
	static CString TimeToString(int64_t time, bool includeMS = false);
	static CString FormatSize(long long size);
	static CString TimeSpanToString(long long ts);
	static PCWSTR IntegrityLevelToString(WinSys::IntegrityLevel level);
	static CString PrivilegeAttributesToString(DWORD pattributes);
	static PCWSTR VirtualizationStateToString(WinSys::VirtualizationState state);
	static CString ProcessAttributesToString(ProcessAttributes attributes);
	static CString ProcessProtectionToString(WinSys::ProcessProtection pp);
	static PCWSTR IoPriorityToString(WinSys::IoPriority io);
};

