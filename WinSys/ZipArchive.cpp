#include "pch.h"
#include "ZipArchive.h"

using namespace WinSys;

bool ZipArchive::Extract(std::wstring const& zip, std::wstring const& folder, uint32_t timeoutMs) {
	WCHAR system[MAX_PATH];
	if (!::GetSystemDirectory(system, _countof(system)))
		return false;
	auto tar = std::wstring(system) + L"\\tar.exe";
	// -x extract, -f the archive, -C into the folder
	auto commandLine = L"\"" + tar + L"\" -xf \"" + zip + L"\" -C \"" + folder + L"\"";
	STARTUPINFO si{ sizeof(si) };
	PROCESS_INFORMATION pi;
	if (!::CreateProcess(tar.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		return false;
	::CloseHandle(pi.hThread);
	DWORD code = 1;
	auto wait = ::WaitForSingleObject(pi.hProcess, timeoutMs);
	if (wait == WAIT_OBJECT_0)
		::GetExitCodeProcess(pi.hProcess, &code);
	else
		::TerminateProcess(pi.hProcess, 1);
	::CloseHandle(pi.hProcess);
	if (wait != WAIT_OBJECT_0) {
		::SetLastError(ERROR_TIMEOUT);
		return false;
	}
	if (code != 0) {
		::SetLastError(ERROR_BAD_FORMAT);
		return false;
	}
	return true;
}
