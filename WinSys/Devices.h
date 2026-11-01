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

	struct Devices final {
		// the tree depth-first (a parent before its children), then the disconnected devices if asked for; nothing (the
		// last error set) if the root can't be located
		[[nodiscard]] static std::optional<std::vector<DeviceInfo>> Enum(bool disconnected = false);
		// a CM_PROB_* code in words ("The device can't start (code 10)")
		[[nodiscard]] static std::wstring ProblemText(uint32_t problem);
	};
}
