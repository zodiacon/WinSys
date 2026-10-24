#include "pch.h"
#include "Power.h"
#include "SecurityHelper.h"
#include <powrprof.h>

#pragma comment(lib, "powrprof")

using namespace WinSys;

namespace {
	// EFI_GLOBAL_VARIABLE, as the Win32 firmware functions take it
	const PCWSTR GlobalVariable = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
	const uint64_t BootToFirmwareUI = 0x1;	// EFI_OS_INDICATIONS_BOOT_TO_FW_UI
	// NV | BS | RT, as OsIndications is defined
	const DWORD OsIndicationsAttributes = 0x7;

	const DWORD Reason = SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED;

	bool Initiate(DWORD flags) {
		SecurityHelper::EnablePrivilege(SE_SHUTDOWN_NAME, true);
		auto error = ::InitiateShutdown(nullptr, nullptr, 0, flags, Reason);
		if (error != ERROR_SUCCESS) {
			::SetLastError(error);
			return false;
		}
		return true;
	}

	std::optional<uint64_t> ReadIndications(PCWSTR name) {
		SecurityHelper::EnablePrivilege(SE_SYSTEM_ENVIRONMENT_NAME, true);
		uint64_t value = 0;
		DWORD attributes = 0;
		// a variable may be shorter than 8 bytes
		auto size = ::GetFirmwareEnvironmentVariableEx(name, GlobalVariable, &value, sizeof(value), &attributes);
		if (size == 0)
			return std::nullopt;
		return value;
	}
}

bool Power::Lock() {
	return ::LockWorkStation();
}

bool Power::LogOff(bool force) {
	return ::ExitWindowsEx(EWX_LOGOFF | (force ? EWX_FORCE : 0), Reason);
}

bool Power::Sleep() {
	SecurityHelper::EnablePrivilege(SE_SHUTDOWN_NAME, true);
	return ::SetSuspendState(FALSE, FALSE, FALSE);
}

bool Power::Hibernate() {
	SecurityHelper::EnablePrivilege(SE_SHUTDOWN_NAME, true);
	return ::SetSuspendState(TRUE, FALSE, FALSE);
}

bool Power::Restart(bool force) {
	return Initiate(SHUTDOWN_RESTART | (force ? SHUTDOWN_FORCE_OTHERS | SHUTDOWN_FORCE_SELF : 0));
}

bool Power::Shutdown(bool force) {
	return Initiate(SHUTDOWN_POWEROFF | (force ? SHUTDOWN_FORCE_OTHERS | SHUTDOWN_FORCE_SELF : 0));
}

bool Power::RestartToBootOptions() {
	return Initiate(SHUTDOWN_RESTART | SHUTDOWN_RESTART_BOOTOPTIONS);
}

bool Power::RestartToFirmware() {
	if (!CanRestartToFirmware()) {
		if (::GetLastError() == ERROR_SUCCESS)
			::SetLastError(ERROR_NOT_SUPPORTED);
		return false;
	}
	// the bit is added to what's there (the variable may not exist yet)
	uint64_t indications = ReadIndications(L"OsIndications").value_or(0) | BootToFirmwareUI;
	if (!::SetFirmwareEnvironmentVariableEx(L"OsIndications", GlobalVariable, &indications, sizeof(indications), OsIndicationsAttributes))
		return false;
	return Restart();
}

bool Power::CanSleep() {
	SYSTEM_POWER_CAPABILITIES caps;
	return ::GetPwrCapabilities(&caps) && (caps.SystemS1 || caps.SystemS2 || caps.SystemS3);
}

bool Power::CanHibernate() {
	SYSTEM_POWER_CAPABILITIES caps;
	return ::GetPwrCapabilities(&caps) && caps.SystemS4 && caps.HiberFilePresent;
}

bool Power::CanRestartToFirmware() {
	FIRMWARE_TYPE type;
	if (!::GetFirmwareType(&type) || type != FirmwareTypeUefi)
		return false;
	auto supported = ReadIndications(L"OsIndicationsSupported");
	return supported && (*supported & BootToFirmwareUI);
}
