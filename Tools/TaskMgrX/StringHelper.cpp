#include "pch.h"
#include "StringHelper.h"
#include "Processes.h"
#include <atltime.h>

PCWSTR StringHelper::PriorityClassToString(PriorityClass pc) {
	switch (pc) {
		case PriorityClass::Normal: return L"Normal (8)";
		case PriorityClass::AboveNormal: return L"Above Normal (10)";
		case PriorityClass::BelowNormal: return L"Below Normal (6)";
		case PriorityClass::High: return L"High (13)";
		case PriorityClass::Idle: return L"Idle (4)";
		case PriorityClass::Realtime: return L"Realtime (24)";
	}
	return L"";
}

CString StringHelper::FormatSize(long long size) {
	CString result;
	int len = ::GetNumberFormat(LOCALE_USER_DEFAULT, 0, std::to_wstring(size).c_str(), nullptr, result.GetBufferSetLength(32), 32);
	return result.Left(len - 4);
}

CString StringHelper::TimeToString(int64_t time, bool includeMS) {
	if (time == 0)
		return L"";
	auto str = CTime(*(FILETIME*)&time).Format(L"%x %X");
	if (includeMS) {
		str.Format(L"%s.%03d", str, (time / 10000) % 1000);
	}
	return str;
}
