#pragma once

#include <processes.h>

struct StringHelper abstract final {
	static PCWSTR PriorityClassToString(PriorityClass pc);
	static CString TimeToString(int64_t time, bool includeMS = false);
	static CString FormatSize(long long size);
	static CString TimeSpanToString(long long ts);
	static PCWSTR IntegrityLevelToString(IntegrityLevel level);
	static CString PrivilegeAttributesToString(DWORD pattributes);
	static PCWSTR VirtualizationStateToString(VirtualizationState state);
};

