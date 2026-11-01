#include "pch.h"
#include "WindowStations.h"
#include "ObjectNamespace.h"
#include <algorithm>

using namespace WinSys;

namespace {
	std::wstring ObjectName(HANDLE hObject) {
		WCHAR name[256]{};
		DWORD needed = 0;
		return ::GetUserObjectInformationW(hObject, UOI_NAME, name, sizeof(name), &needed) ? name : L"";
	}

	DesktopInfo ReadDesktop(std::wstring const& name, std::wstring const& inputDesktop, bool own) {
		DesktopInfo d;
		d.Name = name;
		// only the caller's own station's desktops open by name (OpenDesktop looks in the process's window station)
		if (!own)
			return d;
		if (auto hDesktop = ::OpenDesktopW(name.c_str(), 0, FALSE, DESKTOP_READOBJECTS)) {
			d.Opened = true;
			ULONG heap = 0;
			DWORD needed = 0;
			if (::GetUserObjectInformationW(hDesktop, UOI_HEAPSIZE, &heap, sizeof(heap), &needed))
				d.HeapSizeKB = heap;
			::CloseDesktop(hDesktop);
		}
		d.Input = _wcsicmp(name.c_str(), inputDesktop.c_str()) == 0;
		return d;
	}
}

std::optional<std::vector<WindowStationInfo>> WindowStations::Enum() {
	auto sessions = ObjectNamespace::EnumDirectory(L"\\Sessions");
	if (!sessions)
		return std::nullopt;

	DWORD session = 0;
	::ProcessIdToSessionId(::GetCurrentProcessId(), &session);
	auto ownStation = ObjectName(::GetProcessWindowStation());
	std::wstring inputDesktop;
	if (auto hInput = ::OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS)) {
		inputDesktop = ObjectName(hInput);
		::CloseDesktop(hInput);
	}

	std::vector<WindowStationInfo> stations;
	for (auto& entry : *sessions) {
		// the numbered directories are the sessions (BNOLINKS and the like aren't)
		if (entry.TypeName != L"Directory" || entry.Name.empty() || !std::all_of(entry.Name.begin(), entry.Name.end(), ::iswdigit))
			continue;
		auto id = (uint32_t)std::wcstoul(entry.Name.c_str(), nullptr, 10);
		auto names = ObjectNamespace::EnumDirectory(L"\\Sessions\\" + entry.Name + L"\\Windows\\WindowStations");
		if (!names)
			continue;
		for (auto& n : *names) {
			if (n.TypeName != L"WindowStation")
				continue;
			WindowStationInfo s;
			s.Session = id;
			s.Name = n.Name;
			s.CurrentSession = id == session;
			s.Own = s.CurrentSession && _wcsicmp(n.Name.c_str(), ownStation.c_str()) == 0;
			if (s.CurrentSession) {
				if (auto hStation = ::OpenWindowStationW(n.Name.c_str(), FALSE, WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES)) {
					s.Opened = true;
					USEROBJECTFLAGS flags{};
					DWORD needed = 0;
					if (::GetUserObjectInformationW(hStation, UOI_FLAGS, &flags, sizeof(flags), &needed))
						s.Visible = (flags.dwFlags & WSF_VISIBLE) != 0;
					std::vector<std::wstring> desktops;
					::EnumDesktopsW(hStation, [](LPWSTR name, LPARAM param) -> BOOL {
						reinterpret_cast<std::vector<std::wstring>*>(param)->push_back(name);
						return TRUE;
						}, reinterpret_cast<LPARAM>(&desktops));
					for (auto& d : desktops)
						s.Desktops.push_back(ReadDesktop(d, inputDesktop, s.Own));
					::CloseWindowStation(hStation);
				}
			}
			stations.push_back(std::move(s));
		}
	}
	std::sort(stations.begin(), stations.end(), [](auto& a, auto& b) {
		return a.Session != b.Session ? a.Session < b.Session : _wcsicmp(a.Name.c_str(), b.Name.c_str()) < 0;
		});
	return stations;
}

std::optional<std::vector<WindowInfo>> WindowStations::EnumDesktopWindows(std::wstring const& desktop) {
	auto hDesktop = ::OpenDesktopW(desktop.c_str(), 0, FALSE, DESKTOP_ENUMERATE | DESKTOP_READOBJECTS);
	if (!hDesktop)
		return std::nullopt;
	// the handles first, then each read: a window may go meanwhile
	std::vector<HWND> handles;
	::EnumDesktopWindows(hDesktop, [](HWND hWnd, LPARAM param) -> BOOL {
		reinterpret_cast<std::vector<HWND>*>(param)->push_back(hWnd);
		return TRUE;
		}, reinterpret_cast<LPARAM>(&handles));
	::CloseDesktop(hDesktop);
	std::vector<WindowInfo> windows;
	windows.reserve(handles.size());
	for (auto h : handles)
		if (::IsWindow(h))
			windows.push_back(ProcessWindows::Describe(h));
	return windows;
}
