#include "pch.h"
#include "Helpers.h"

using namespace WinSys;

std::wstring Helpers::GetDosNameFromNtName(PCWSTR name, bool refresh) {
	// shared by every thread (the UI's, the property sheets'): built again when the drives change, under a lock
	static SRWLOCK lock = SRWLOCK_INIT;
	static std::vector<std::pair<std::wstring, std::wstring>> deviceNames;	// "\Device\HarddiskVolume3", "C:"
	static DWORD tableDrives = 0;
	static bool first = true;

	auto drives = ::GetLogicalDrives();
	::AcquireSRWLockExclusive(&lock);
	if (first || refresh || drives != tableDrives) {
		deviceNames.clear();
		for (int drive = 0; drive < 26; drive++) {
			if ((drives & (1 << drive)) == 0)
				continue;
			WCHAR driveName[] = L"X:";
			driveName[0] = (WCHAR)(drive + 'A');
			WCHAR path[MAX_PATH];
			if (::QueryDosDevice(driveName, path, MAX_PATH))
				deviceNames.push_back({ path, driveName });
		}
		tableDrives = drives;
		first = false;
	}

	std::wstring dos;
	for (auto& [ntName, dosName] : deviceNames) {
		// the whole device name: \Device\HarddiskVolume1 isn't the start of \Device\HarddiskVolume12\...
		if (::_wcsnicmp(name, ntName.c_str(), ntName.size()) != 0)
			continue;
		if (auto rest = name + ntName.size(); *rest == L'\\' || *rest == 0) {
			dos = dosName + rest;
			break;
		}
	}
	::ReleaseSRWLockExclusive(&lock);
	return dos;
}

std::wstring Helpers::GetErrorText(DWORD error) {
	PWSTR buffer;
	std::wstring text;
	if (::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		0, error, 0, (LPTSTR)&buffer, 0, nullptr) > 0) {
		text = buffer;
		::LocalFree(buffer);
	}
	// system messages end with a line break
	while (!text.empty() && ::iswspace(text.back()))
		text.pop_back();
	return text;
}

int Helpers::PriorityClassToPriority(ProcessPriorityClass pc) {
	switch (pc) {
		case ProcessPriorityClass::Normal: return 8;
		case ProcessPriorityClass::AboveNormal: return 10;
		case ProcessPriorityClass::BelowNormal: return 6;
		case ProcessPriorityClass::High: return 13;
		case ProcessPriorityClass::Idle: return 4;
		case ProcessPriorityClass::Realtime: return 24;
	}
	return 0;
}