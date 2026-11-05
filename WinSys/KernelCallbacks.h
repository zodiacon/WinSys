#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// What hooks into the kernel's notifications: the file system minifilters the Filter Manager has (FilterFindFirst and
// FilterInstanceFindFirst, fltlib: what fltmc shows; administrator rights needed), with their instances on volumes, and
// the loaded drivers that import a callback registration function (PsSetCreateProcessNotifyRoutineEx, CmRegisterCallbackEx,
// ObRegisterCallbacks, FltRegisterFilter, FwpsCalloutRegister...), read from their files' import tables.
//
// The kernel's callback arrays themselves (PspCreateProcessNotifyRoutine and the rest) are in kernel memory, which user
// mode can't read without a driver: an import says what a driver can register, not that it did (most drivers that import
// one call it in their DriverEntry, though). The kernel's own registrations (ntoskrnl calls them directly) don't show.
//
namespace WinSys {
	struct MinifilterInstance {
		std::wstring Name;			// "WdFilter Instance"
		std::wstring Altitude;
		std::wstring Volume;		// "\Device\HarddiskVolume3", or a redirector's "\Device\Mup"
		std::wstring DosVolume;		// "C:" when the volume has a drive letter (FilterGetDosName)
		uint32_t FileSystem{ 0 };	// FLT_FILESYSTEM_TYPE
		uint32_t FrameId{ 0 };
		bool Detached{ false };		// FLTFL_IASIM_DETACHED_VOLUME: the volume isn't attached to a storage stack
		bool Legacy{ false };
	};

	struct Minifilter {
		std::wstring Name;			// the filter's (its driver's service) name
		std::wstring Altitude;		// "328010": the higher, the closer to the I/O manager
		uint32_t FrameId{ 0 };
		uint32_t InstanceCount{ 0 };	// as the filter manager counts them
		bool Legacy{ false };		// a legacy file system filter driver (not a minifilter), seen by the filter manager
		std::wstring ImagePath;		// the service's image, as a Win32 path (KernelModules::DriverImagePath); empty without a service
		std::vector<MinifilterInstance> Instances;
	};

	// what a registration function hooks; a driver's kinds are the bits of those it imports
	enum class CallbackKind : uint32_t {
		None = 0,
		Process = 1 << 0,			// process creation and exit
		Thread = 1 << 1,			// thread creation and exit
		ImageLoad = 1 << 2,			// image (executable, DLL, driver) mapping
		Registry = 1 << 3,			// registry operations, before and after
		Object = 1 << 4,			// handle opens and duplications of processes, threads, desktops
		FileSystem = 1 << 5,		// a minifilter (FltRegisterFilter), or a legacy file system filter
		Network = 1 << 6,			// WFP callouts, NDIS filters
		BootDriver = 1 << 7,		// boot-start drivers' initialization (Early Launch Antimalware)
		BugCheck = 1 << 8,
		Shutdown = 1 << 9,
		Power = 1 << 10,			// power settings
		CallbackObject = 1 << 11,	// an executive callback object (\Callback\PowerState, \Callback\SetSystemTime...)
		PlugAndPlay = 1 << 12,		// device arrival and removal, interface changes
		Session = 1 << 13,			// user sessions' changes
		Nmi = 1 << 14,				// non-maskable interrupts
		DebugPrint = 1 << 15,		// the kernel's DbgPrint output
		LogonSession = 1 << 16,		// logon sessions' termination
	};
	constexpr CallbackKind operator|(CallbackKind a, CallbackKind b) { return CallbackKind((uint32_t)a | (uint32_t)b); }
	constexpr CallbackKind operator&(CallbackKind a, CallbackKind b) { return CallbackKind((uint32_t)a & (uint32_t)b); }
	constexpr CallbackKind& operator|=(CallbackKind& a, CallbackKind b) { return a = a | b; }

	struct CallbackImport {
		std::string Function;		// "PsSetCreateProcessNotifyRoutineEx"
		std::string Library;		// "ntoskrnl.exe", "FLTMGR.SYS"
		CallbackKind Kind{ CallbackKind::None };
	};

	struct CallbackDriver {
		std::wstring Name;			// the module's file name
		std::wstring Path;			// a Win32 path
		uint16_t LoadOrder{ 0 };
		CallbackKind Kinds{ CallbackKind::None };
		std::vector<CallbackImport> Imports;	// the registration functions, in the import table's order
	};

	struct CallbackDrivers {
		std::vector<CallbackDriver> Drivers;	// those that import a registration function, in the kernel's load order
		uint32_t Modules{ 0 };					// the loaded modules looked at
		std::vector<std::wstring> Unreadable;	// the modules whose files couldn't be read or parsed
	};

	struct KernelCallbacks final {
		// the filters, by altitude (highest first); nothing (the last error set: ERROR_ACCESS_DENIED when not elevated)
		// if the filter manager can't be asked
		[[nodiscard]] static std::optional<std::vector<Minifilter>> EnumMinifilters();
		// reads every loaded module's file (a second or so)
		[[nodiscard]] static CallbackDrivers EnumCallbackDrivers();

		// a function's kind (exact names; the numbered ones, FwpsCalloutRegister0 to 3, by their stem); None if it isn't
		// a registration function
		[[nodiscard]] static CallbackKind KindOf(std::string_view function);
		// what a registration function does, for a tooltip or a details column; empty if it isn't one
		[[nodiscard]] static PCWSTR Describe(std::string_view function);
		// "Process" for one kind; "Process, Thread, Registry" for several, in the bits' order
		[[nodiscard]] static std::wstring KindsText(CallbackKind kinds);
		[[nodiscard]] static PCWSTR FileSystemName(uint32_t type);	// FLT_FILESYSTEM_TYPE: "NTFS", "ReFS", "Mup"...
	};
}
