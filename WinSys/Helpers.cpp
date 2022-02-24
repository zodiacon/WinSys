#include "pch.h"
#include "Helpers.h"

#ifdef WINSYS_NAMESPACE
using namespace WinSys;
#endif

std::wstring Helpers::GetDosNameFromNtName(PCWSTR name, bool refresh) {
	static std::vector<std::pair<std::wstring, std::wstring>> deviceNames;
	static bool first = true;
	if (first || refresh) {
		deviceNames.clear();
		auto drives = ::GetLogicalDrives();
		int drive = 0;
		while (drives) {
			if (drives & 1) {
				// drive exists
				WCHAR driveName[] = L"X:";
				driveName[0] = (WCHAR)(drive + 'A');
				WCHAR path[MAX_PATH];
				if (::QueryDosDevice(driveName, path, MAX_PATH)) {
					deviceNames.push_back({ path, driveName });
				}
			}
			drive++;
			drives >>= 1;
		}
		first = false;
	}

	for (auto& [ntName, dosName] : deviceNames) {
		if (::_wcsnicmp(name, ntName.c_str(), ntName.size()) == 0)
			return dosName + (name + ntName.size());
	}
	return L"";
}

std::wstring Helpers::GetErrorText(DWORD error) {
	PWSTR buffer;
	std::wstring text;
	if (::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		0, error, 0, (LPTSTR)&buffer, 0, nullptr) > 0) {
		text = buffer;
		::LocalFree(buffer);
	}
	return text;
}

int Helpers::PriorityClassToPriority(PriorityClass pc) {
	switch (pc) {
		case PriorityClass::Normal: return 8;
		case PriorityClass::AboveNormal: return 10;
		case PriorityClass::BelowNormal: return 6;
		case PriorityClass::High: return 13;
		case PriorityClass::Idle: return 4;
		case PriorityClass::Realtime: return 24;
	}
	return 0;
}