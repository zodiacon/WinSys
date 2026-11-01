#include "pch.h"
#include "Devices.h"
#include <cfgmgr32.h>
#include <devpkey.h>
#include <SetupAPI.h>
#include <unordered_set>

#pragma comment(lib, "cfgmgr32")
#pragma comment(lib, "setupapi")

using namespace WinSys;

namespace {
	// a string property (empty if there's none)
	std::wstring StringProperty(DEVINST devInst, DEVPROPKEY const& key) {
		DEVPROPTYPE type;
		ULONG size = 0;
		if (::CM_Get_DevNode_PropertyW(devInst, &key, &type, nullptr, &size, 0) != CR_BUFFER_SMALL || size == 0)
			return L"";
		std::wstring value(size / sizeof(WCHAR), L'\0');
		if (::CM_Get_DevNode_PropertyW(devInst, &key, &type, (PBYTE)value.data(), &size, 0) != CR_SUCCESS || type != DEVPROP_TYPE_STRING)
			return L"";
		value.resize(::wcsnlen(value.c_str(), value.size()));
		return value;
	}

	int64_t FileTimeProperty(DEVINST devInst, DEVPROPKEY const& key) {
		DEVPROPTYPE type;
		FILETIME ft{};
		ULONG size = sizeof(ft);
		if (::CM_Get_DevNode_PropertyW(devInst, &key, &type, (PBYTE)&ft, &size, 0) != CR_SUCCESS || type != DEVPROP_TYPE_FILETIME)
			return 0;
		return (int64_t)ULARGE_INTEGER{ ft.dwLowDateTime, ft.dwHighDateTime }.QuadPart;
	}

	std::wstring GuidProperty(DEVINST devInst, DEVPROPKEY const& key) {
		DEVPROPTYPE type;
		GUID guid{};
		ULONG size = sizeof(guid);
		if (::CM_Get_DevNode_PropertyW(devInst, &key, &type, (PBYTE)&guid, &size, 0) != CR_SUCCESS || type != DEVPROP_TYPE_GUID)
			return L"";
		WCHAR text[64];
		return ::StringFromGUID2(guid, text, _countof(text)) ? text : L"";
	}

	DeviceInfo Read(DEVINST devInst) {
		DeviceInfo d;
		WCHAR id[MAX_DEVICE_ID_LEN + 1]{};
		if (::CM_Get_Device_IDW(devInst, id, _countof(id), 0) == CR_SUCCESS)
			d.InstanceId = id;
		d.Description = StringProperty(devInst, DEVPKEY_Device_DeviceDesc);
		d.Name = StringProperty(devInst, DEVPKEY_Device_FriendlyName);
		if (d.Name.empty())
			d.Name = d.Description;
		d.Class = StringProperty(devInst, DEVPKEY_Device_Class);
		d.ClassGuid = GuidProperty(devInst, DEVPKEY_Device_ClassGuid);
		d.Manufacturer = StringProperty(devInst, DEVPKEY_Device_Manufacturer);
		d.Service = StringProperty(devInst, DEVPKEY_Device_Service);
		d.DriverVersion = StringProperty(devInst, DEVPKEY_Device_DriverVersion);
		d.DriverProvider = StringProperty(devInst, DEVPKEY_Device_DriverProvider);
		d.InfPath = StringProperty(devInst, DEVPKEY_Device_DriverInfPath);
		d.DriverDate = FileTimeProperty(devInst, DEVPKEY_Device_DriverDate);
		d.Location = StringProperty(devInst, DEVPKEY_Device_LocationInfo);
		d.PdoName = StringProperty(devInst, DEVPKEY_Device_PDOName);
		d.Enumerator = StringProperty(devInst, DEVPKEY_Device_EnumeratorName);
		ULONG status = 0, problem = 0;
		if (::CM_Get_DevNode_Status(&status, &problem, devInst, 0) == CR_SUCCESS) {
			d.Status = status;
			d.Problem = (status & DN_HAS_PROBLEM) ? problem : 0;
		}
		return d;
	}

	// the classes' descriptions, as Device Manager shows them ("Network adapters"), once per class
	void SetClassNames(std::vector<DeviceInfo>& devices) {
		std::unordered_map<std::wstring, std::wstring> names;
		for (auto& d : devices) {
			if (d.ClassGuid.empty()) {
				d.ClassName = d.Class;
				continue;
			}
			auto it = names.find(d.ClassGuid);
			if (it == names.end()) {
				std::wstring name;
				GUID guid;
				if (SUCCEEDED(::CLSIDFromString(d.ClassGuid.c_str(), &guid))) {
					DEVPROPTYPE type;
					WCHAR text[256]{};
					ULONG size = sizeof(text);
					if (::CM_Get_Class_PropertyW(&guid, &DEVPKEY_NAME, &type, (PBYTE)text, &size, 0) == CR_SUCCESS && type == DEVPROP_TYPE_STRING)
						name = text;
				}
				it = names.insert({ d.ClassGuid, name.empty() ? d.Class : name }).first;
			}
			d.ClassName = it->second;
		}
	}

	void Walk(DEVINST devInst, int parent, int depth, std::vector<DeviceInfo>& devices) {
		// siblings in a loop, children by recursion (the tree is a few levels deep)
		for (bool more = true; more; ) {
			auto device = Read(devInst);
			device.Parent = parent;
			device.Depth = depth;
			devices.push_back(std::move(device));
			int index = (int)devices.size() - 1;
			DEVINST child;
			if (::CM_Get_Child(&child, devInst, 0) == CR_SUCCESS)
				Walk(child, index, depth + 1, devices);
			// the root has no siblings
			more = parent >= 0 && ::CM_Get_Sibling(&devInst, devInst, 0) == CR_SUCCESS;
		}
	}
}

bool DeviceInfo::HasProblem() const {
	return (Status & DN_HAS_PROBLEM) != 0 && Problem != CM_PROB_DISABLED;
}

bool DeviceInfo::IsDisabled() const {
	return (Status & DN_HAS_PROBLEM) != 0 && Problem == CM_PROB_DISABLED;
}

bool DeviceInfo::IsHidden() const {
	return (Status & DN_NO_SHOW_IN_DM) != 0;
}

std::optional<std::vector<DeviceInfo>> Devices::Enum(bool disconnected) {
	DEVINST root;
	auto cr = ::CM_Locate_DevNodeW(&root, nullptr, CM_LOCATE_DEVNODE_NORMAL);
	if (cr != CR_SUCCESS) {
		::SetLastError(::CM_MapCrToWin32Err(cr, ERROR_NOT_FOUND));
		return std::nullopt;
	}
	std::vector<DeviceInfo> devices;
	devices.reserve(512);
	Walk(root, -1, 0, devices);

	if (disconnected) {
		std::unordered_set<std::wstring> present;
		for (auto& d : devices)
			present.insert(d.InstanceId);
		ULONG length = 0;
		if (::CM_Get_Device_ID_List_SizeW(&length, nullptr, CM_GETIDLIST_FILTER_NONE) == CR_SUCCESS && length) {
			std::vector<WCHAR> ids(length);
			if (::CM_Get_Device_ID_ListW(nullptr, ids.data(), length, CM_GETIDLIST_FILTER_NONE) == CR_SUCCESS) {
				for (auto p = ids.data(); *p; p += wcslen(p) + 1) {
					if (present.contains(p))
						continue;
					DEVINST devInst;
					if (::CM_Locate_DevNodeW(&devInst, p, CM_LOCATE_DEVNODE_PHANTOM) != CR_SUCCESS)
						continue;
					auto device = Read(devInst);
					device.Present = false;
					devices.push_back(std::move(device));
				}
			}
		}
	}
	SetClassNames(devices);
	return devices;
}

std::wstring Devices::ProblemText(uint32_t problem) {
	static const struct {
		uint32_t Code;
		PCWSTR Text;
	} texts[] = {
		{ CM_PROB_NOT_CONFIGURED, L"Not configured" },
		{ CM_PROB_DEVLOADER_FAILED, L"The driver loader failed" },
		{ CM_PROB_OUT_OF_MEMORY, L"Out of memory" },
		{ CM_PROB_ENTRY_IS_WRONG_TYPE, L"Wrong type" },
		{ CM_PROB_LACKED_ARBITRATOR, L"No arbitrator" },
		{ CM_PROB_BOOT_CONFIG_CONFLICT, L"Boot configuration conflict" },
		{ CM_PROB_FAILED_FILTER, L"A filter driver failed" },
		{ CM_PROB_DEVLOADER_NOT_FOUND, L"The driver loader wasn't found" },
		{ CM_PROB_INVALID_DATA, L"Invalid data" },
		{ CM_PROB_FAILED_START, L"The device can't start" },
		{ CM_PROB_LIAR, L"The device failed" },
		{ CM_PROB_NORMAL_CONFLICT, L"Resource conflict" },
		{ CM_PROB_NOT_VERIFIED, L"Not verified" },
		{ CM_PROB_NEED_RESTART, L"Needs a restart" },
		{ CM_PROB_REENUMERATION, L"Reenumeration" },
		{ CM_PROB_PARTIAL_LOG_CONF, L"Partial configuration" },
		{ CM_PROB_UNKNOWN_RESOURCE, L"Unknown resource type" },
		{ CM_PROB_REINSTALL, L"The drivers must be reinstalled" },
		{ CM_PROB_REGISTRY, L"Registry problem" },
		{ CM_PROB_WILL_BE_REMOVED, L"Will be removed" },
		{ CM_PROB_DISABLED, L"Disabled" },
		{ CM_PROB_DEVICE_NOT_THERE, L"Not present" },
		{ CM_PROB_MOVED, L"Moved" },
		{ CM_PROB_TOO_EARLY, L"Too early" },
		{ CM_PROB_NO_VALID_LOG_CONF, L"No valid configuration" },
		{ CM_PROB_FAILED_INSTALL, L"The drivers aren't installed" },
		{ CM_PROB_HARDWARE_DISABLED, L"Disabled by the firmware" },
		{ CM_PROB_CANT_SHARE_IRQ, L"Can't share an IRQ" },
		{ CM_PROB_FAILED_ADD, L"The driver failed to add the device" },
		{ CM_PROB_DISABLED_SERVICE, L"The driver's service is disabled" },
		{ CM_PROB_TRANSLATION_FAILED, L"Resource translation failed" },
		{ CM_PROB_NO_SOFTCONFIG, L"No soft configuration" },
		{ CM_PROB_BIOS_TABLE, L"BIOS table problem" },
		{ CM_PROB_IRQ_TRANSLATION_FAILED, L"IRQ translation failed" },
		{ CM_PROB_FAILED_DRIVER_ENTRY, L"The driver failed to load" },
		{ CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD, L"A previous instance of the driver is still loaded" },
		{ CM_PROB_DRIVER_FAILED_LOAD, L"The driver failed to load" },
		{ CM_PROB_DRIVER_SERVICE_KEY_INVALID, L"The driver's service key is invalid" },
		{ CM_PROB_LEGACY_SERVICE_NO_DEVICES, L"A legacy service with no devices" },
		{ CM_PROB_DUPLICATE_DEVICE, L"Duplicate device" },
		{ CM_PROB_FAILED_POST_START, L"The device reported a problem" },
		{ CM_PROB_HALTED, L"Halted" },
		{ CM_PROB_PHANTOM, L"Not connected" },
		{ CM_PROB_SYSTEM_SHUTDOWN, L"The system is shutting down" },
		{ CM_PROB_HELD_FOR_EJECT, L"Held for ejection" },
		{ CM_PROB_DRIVER_BLOCKED, L"The driver is blocked" },
		{ CM_PROB_REGISTRY_TOO_LARGE, L"The registry is too large" },
		{ CM_PROB_SETPROPERTIES_FAILED, L"Setting its properties failed" },
		{ CM_PROB_WAITING_ON_DEPENDENCY, L"Waiting on a dependency" },
		{ CM_PROB_UNSIGNED_DRIVER, L"The driver isn't signed" },
		{ CM_PROB_USED_BY_DEBUGGER, L"Used by the debugger" },
		{ CM_PROB_DEVICE_RESET, L"Being reset" },
		{ CM_PROB_CONSOLE_LOCKED, L"The console is locked" },
		{ CM_PROB_NEED_CLASS_CONFIG, L"Needs class configuration" },
	};
	for (auto& t : texts)
		if (t.Code == problem)
			return std::wstring(t.Text) + L" (code " + std::to_wstring(problem) + L")";
	return L"Problem code " + std::to_wstring(problem);
}

DeviceChangeResult Devices::SetEnabled(std::wstring const& instanceId, bool enable) {
	auto hInfo = ::SetupDiCreateDeviceInfoList(nullptr, nullptr);
	if (hInfo == INVALID_HANDLE_VALUE)
		return DeviceChangeResult::Failed;
	auto result = DeviceChangeResult::Failed;
	SP_DEVINFO_DATA device{ sizeof(device) };
	if (::SetupDiOpenDeviceInfoW(hInfo, instanceId.c_str(), nullptr, 0, &device)) {
		SP_PROPCHANGE_PARAMS params{};
		params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
		params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
		params.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;
		params.Scope = DICS_FLAG_GLOBAL;
		params.HwProfile = 0;
		if (::SetupDiSetClassInstallParamsW(hInfo, &device, &params.ClassInstallHeader, sizeof(params))
			&& ::SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hInfo, &device)) {
			SP_DEVINSTALL_PARAMS_W install{ sizeof(install) };
			result = ::SetupDiGetDeviceInstallParamsW(hInfo, &device, &install) && (install.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT))
				? DeviceChangeResult::RestartNeeded : DeviceChangeResult::Done;
		}
	}
	auto error = ::GetLastError();
	::SetupDiDestroyDeviceInfoList(hInfo);
	::SetLastError(error);
	return result;
}

bool Devices::ScanForChanges() {
	DEVINST root;
	auto cr = ::CM_Locate_DevNodeW(&root, nullptr, CM_LOCATE_DEVNODE_NORMAL);
	if (cr == CR_SUCCESS)
		cr = ::CM_Reenumerate_DevNode(root, CM_REENUMERATE_ASYNCHRONOUS);	// synchronous takes seconds
	if (cr != CR_SUCCESS) {
		::SetLastError(::CM_MapCrToWin32Err(cr, ERROR_ACCESS_DENIED));
		return false;
	}
	return true;
}
