#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// The device tree, as Device Manager shows it (CfgMgr32): the devices from the root down (CM_Get_Child/CM_Get_Sibling),
// each with its properties (CM_Get_DevNode_Property: name, class (with its description, CM_Get_Class_Property's
// DEVPKEY_NAME), manufacturer, driver service, version, date,
// provider, INF, location, PDO name, enumerator) and status (CM_Get_DevNode_Status: a problem code when it has one).
// Disconnected devices (installed, not present: CM_Get_Device_ID_List with every ID, located as phantoms) come after
// the tree when asked for, with no parent. No elevation needed.
//

namespace WinSys {
	struct DeviceInfo {
		std::wstring InstanceId;		// "PCI\VEN_10DE&DEV_2684&..."
		std::wstring Name;				// the friendly name, else the description
		std::wstring Description;		// the device description
		std::wstring Class, ClassGuid;
		std::wstring ClassName;		// the class's description ("Network adapters"), else Class
		std::wstring Manufacturer;
		std::wstring Service;			// the driver service
		std::wstring DriverVersion, DriverProvider, InfPath;
		int64_t DriverDate{ 0 };		// FILETIME, 0 if none
		std::wstring Location;			// "PCI bus 1, device 0, function 0"
		std::wstring PdoName;			// "\Device\00000052"
		std::wstring Enumerator;		// "PCI", "USB", "ROOT"...
		uint32_t Status{ 0 };			// DN_* flags
		uint32_t Problem{ 0 };			// CM_PROB_*, when Status has DN_HAS_PROBLEM
		bool Present{ true };
		int Parent{ -1 };				// the parent's index, -1 for the root (and disconnected devices)
		int Depth{ 0 };

		[[nodiscard]] bool HasProblem() const;
		[[nodiscard]] bool IsDisabled() const;
		[[nodiscard]] bool IsHidden() const;	// DN_NO_SHOW_IN_DM
	};

	enum class DeviceResourceType { Memory, LargeMemory, Io, Interrupt, Dma, BusNumber };

	// a resource the device was given (its allocated configuration, else its boot one)
	struct DeviceResource {
		DeviceResourceType Type{ DeviceResourceType::Memory };
		uint64_t Start{ 0 }, End{ 0 };	// a range (memory, I/O, bus numbers)
		uint32_t Value{ 0 };			// an interrupt or DMA channel; a message-signaled interrupt's is negative as an int32
		uint32_t Flags{ 0 };			// the descriptor's (IRQD_Flags, MD_Flags...)
	};

	enum class DriverRole { ClassUpperFilter, UpperFilter, Function, ClassLowerFilter, LowerFilter, Bus };

	// a driver loaded for a device, in the stack's order from the top
	struct DeviceDriver {
		DriverRole Role{ DriverRole::Function };
		std::wstring Service;	// the driver service
		std::wstring Path;		// its image (KernelModules::DriverImagePath), empty if the service has none
	};

	enum class DeviceChangeResult {
		Done,
		RestartNeeded,	// made, takes effect after a restart
		Failed,			// the last error says why
	};

	struct Devices final {
		// the tree depth-first (a parent before its children), then the disconnected devices if asked for; nothing (the
		// last error set) if the root can't be located
		[[nodiscard]] static std::optional<std::vector<DeviceInfo>> Enum(bool disconnected = false);
		// a CM_PROB_* code in words ("The device can't start (code 10)")
		[[nodiscard]] static std::wstring ProblemText(uint32_t problem);

		// Enables or disables a device as Device Manager does: SetupAPI's DIF_PROPERTYCHANGE with DICS_ENABLE or
		// DICS_DISABLE in the global scope (kept across restarts). Needs elevation (ERROR_ACCESS_DENIED otherwise); a device
		// that can't be stopped now asks for a restart (the change is made at the next boot)
		[[nodiscard]] static DeviceChangeResult SetEnabled(std::wstring const& instanceId, bool enable);
		// Device Manager's Scan for hardware changes: the tree enumerated again from the root (CM_Reenumerate_DevNode,
		// asynchronous; arrivals come as device notifications). Needs elevation
		static bool ScanForChanges();

		// the device's resources (CM_Get_First_Log_Conf ALLOC_LOG_CONF, else BOOT_LOG_CONF; each CM_Get_Next_Res_Des with
		// its data): none for a device without (most software devices); nothing (the last error set) if it isn't found
		[[nodiscard]] static std::optional<std::vector<DeviceResource>> GetResources(std::wstring const& instanceId);
		// the drivers loaded for the device, from the top: the class's and the device's upper filters, the function
		// driver (its service), the class's and the device's lower filters, the bus driver (the parent's service)
		[[nodiscard]] static std::optional<std::vector<DeviceDriver>> GetDriverStack(std::wstring const& instanceId);
		[[nodiscard]] static PCWSTR ResourceTypeName(DeviceResourceType type);
		[[nodiscard]] static PCWSTR DriverRoleName(DriverRole role);
		// where a class's icon is (DEVPKEY_DeviceClass_IconPath's first entry: "%SystemRoot%\System32\setupapi.dll,-23",
		// environment variables expanded, the index after the comma: negative is a resource ID), to load it at any size;
		// empty if the class has none
		[[nodiscard]] static std::wstring GetClassIconPath(std::wstring const& classGuid);
	};
}
