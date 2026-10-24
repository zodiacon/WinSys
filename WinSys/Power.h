#pragma once

//
// Ending or suspending the session and the system: lock, log off, sleep, hibernate, restart, shut down, restart into
// the boot options menu (Windows' advanced startup) or into the firmware's setup. Each enables the privilege it needs
// (SeShutdownPrivilege for the power ones, SeSystemEnvironmentPrivilege, so elevation, to request the firmware setup).
// They return false with the last error set on failure; a call that succeeded may still be refused later by an
// application that blocks the shutdown.
//
namespace WinSys {
	struct Power final {
		static bool Lock();
		// force: applications are closed without being asked to save
		static bool LogOff(bool force = false);
		static bool Sleep();
		static bool Hibernate();
		static bool Restart(bool force = false);
		static bool Shutdown(bool force = false);
		// Windows starts into its boot options (advanced startup: troubleshooting, startup settings...)
		static bool RestartToBootOptions();
		// as shutdown /r /fw: sets the firmware's OsIndications to boot into its setup, then restarts
		static bool RestartToFirmware();

		// S1-S3 (not Modern Standby's S0 low power, which SetSuspendState doesn't enter)
		[[nodiscard]] static bool CanSleep();
		// S4 with a hibernation file
		[[nodiscard]] static bool CanHibernate();
		// UEFI firmware that supports booting into its setup (OsIndicationsSupported's EFI_OS_INDICATIONS_BOOT_TO_FW_UI);
		// reading the variable needs elevation, so false without it
		[[nodiscard]] static bool CanRestartToFirmware();
	};
}
