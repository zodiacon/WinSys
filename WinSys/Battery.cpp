#include "pch.h"
#include "Battery.h"
#include <SetupAPI.h>
// phnt defines ThermalStandby (a power information class), which poclass.h has as a THERMAL_POLICY field
#pragma push_macro("ThermalStandby")
#undef ThermalStandby
#include <poclass.h>
#pragma pop_macro("ThermalStandby")
#include <cmath>
#include <algorithm>

#pragma comment(lib, "setupapi")

namespace WinSys {
	namespace {
		// GUID_DEVICE_BATTERY (poclass.h declares it, without INITGUID)
		const GUID BatteryInterface = { 0x72631e54, 0x78a4, 0x11d0, { 0xbc, 0xf7, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a } };

		template<typename T>
		bool Query(HANDLE h, ULONG tag, BATTERY_QUERY_INFORMATION_LEVEL level, T& result) {
			BATTERY_QUERY_INFORMATION query{ tag, level, 0 };
			DWORD bytes = 0;
			return ::DeviceIoControl(h, IOCTL_BATTERY_QUERY_INFORMATION, &query, sizeof(query), &result, sizeof(result), &bytes, nullptr) != FALSE;
		}

		std::wstring QueryString(HANDLE h, ULONG tag, BATTERY_QUERY_INFORMATION_LEVEL level) {
			WCHAR text[256]{};
			BATTERY_QUERY_INFORMATION query{ tag, level, 0 };
			DWORD bytes = 0;
			if (!::DeviceIoControl(h, IOCTL_BATTERY_QUERY_INFORMATION, &query, sizeof(query), text, sizeof(text) - sizeof(WCHAR), &bytes, nullptr))
				return L"";
			return text;
		}

		std::optional<uint32_t> Known(ULONG value, ULONG unknown) {
			return value == unknown ? std::nullopt : std::optional<uint32_t>(value);
		}
	}

	std::optional<float> BatteryInfo::ChargePercent() const {
		if (!Reading.Capacity || !FullChargedCapacity || *FullChargedCapacity == 0)
			return {};
		return std::min(100.0f, 100.0f * *Reading.Capacity / *FullChargedCapacity);
	}

	std::optional<float> BatteryInfo::HealthPercent() const {
		if (!FullChargedCapacity || !DesignedCapacity || *DesignedCapacity == 0 || Relative)
			return {};
		return 100.0f * *FullChargedCapacity / *DesignedCapacity;
	}

	size_t BatteryMonitor::Open() {
		m_Batteries.clear();
		HDEVINFO devices = ::SetupDiGetClassDevs(&BatteryInterface, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
		if (devices == INVALID_HANDLE_VALUE)
			return 0;
		SP_DEVICE_INTERFACE_DATA data{ sizeof(data) };
		for (DWORD i = 0; i < 100 && ::SetupDiEnumDeviceInterfaces(devices, nullptr, &BatteryInterface, i, &data); i++) {
			DWORD size = 0;
			::SetupDiGetDeviceInterfaceDetail(devices, &data, nullptr, 0, &size, nullptr);
			if (size == 0)
				continue;
			std::vector<BYTE> buffer(size);
			auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA*>(buffer.data());
			detail->cbSize = sizeof(*detail);
			if (!::SetupDiGetDeviceInterfaceDetail(devices, &data, detail, size, nullptr, nullptr))
				continue;
			Device device;
			device.Handle.reset(::CreateFile(detail->DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
			if (!device.Handle)
				continue;
			device.Info.DevicePath = detail->DevicePath;
			RefreshTag(device);
			m_Batteries.push_back(std::move(device));
		}
		::SetupDiDestroyDeviceInfoList(devices);
		return m_Batteries.size();
	}

	bool BatteryMonitor::RefreshTag(Device& device) {
		ULONG wait = 0, tag = 0;
		DWORD bytes = 0;
		if (!::DeviceIoControl(device.Handle.get(), IOCTL_BATTERY_QUERY_TAG, &wait, sizeof(wait), &tag, sizeof(tag), &bytes, nullptr) || tag == 0) {
			device.Tag = 0;
			return false;
		}
		if (tag == device.Tag)
			return true;
		// a new battery in the slot: its static information
		device.Tag = tag;
		auto& info = device.Info;
		BATTERY_INFORMATION bi{};
		if (Query(device.Handle.get(), tag, BatteryInformation, bi)) {
			info.Rechargeable = bi.Technology == 1;
			info.Relative = (bi.Capabilities & BATTERY_CAPACITY_RELATIVE) != 0;
			info.DesignedCapacity = Known(bi.DesignedCapacity, BATTERY_UNKNOWN_CAPACITY);
			info.FullChargedCapacity = Known(bi.FullChargedCapacity, BATTERY_UNKNOWN_CAPACITY);
			info.CycleCount = bi.CycleCount;
			std::wstring chemistry;
			for (auto ch : bi.Chemistry)
				if (ch)
					chemistry += (wchar_t)ch;
			info.Chemistry = chemistry;
		}
		info.Name = QueryString(device.Handle.get(), tag, BatteryDeviceName);
		info.Manufacturer = QueryString(device.Handle.get(), tag, BatteryManufactureName);
		return true;
	}

	std::vector<BatteryInfo> BatteryMonitor::Read() {
		std::vector<BatteryInfo> result;
		for (auto& device : m_Batteries) {
			auto info = device.Info;
			info.HasReading = false;
			info.Reading = {};
			if (RefreshTag(device)) {
				info = device.Info;
				auto h = device.Handle.get();
				BATTERY_WAIT_STATUS wait{ device.Tag, 0, 0, 0, 0 };
				BATTERY_STATUS status{};
				DWORD bytes = 0;
				if (::DeviceIoControl(h, IOCTL_BATTERY_QUERY_STATUS, &wait, sizeof(wait), &status, sizeof(status), &bytes, nullptr)) {
					info.HasReading = true;
					auto& r = info.Reading;
					r.PowerState = status.PowerState;
					r.Capacity = Known(status.Capacity, BATTERY_UNKNOWN_CAPACITY);
					r.Voltage = Known(status.Voltage, BATTERY_UNKNOWN_VOLTAGE);
					if ((ULONG)status.Rate != BATTERY_UNKNOWN_RATE)
						r.Rate = status.Rate;
					ULONG seconds = BATTERY_UNKNOWN_TIME;
					if (Query(h, device.Tag, BatteryEstimatedTime, seconds))
						r.EstimatedSeconds = Known(seconds, BATTERY_UNKNOWN_TIME);
					ULONG temperature = 0;
					if (Query(h, device.Tag, BatteryTemperature, temperature) && temperature)
						r.TemperatureC = TenthsKelvinToCelsius(temperature);
				}
			}
			result.push_back(std::move(info));
		}
		return result;
	}

	SystemPowerState BatteryMonitor::GetSystemState() {
		SystemPowerState state;
		SYSTEM_POWER_STATUS status;
		if (!::GetSystemPowerStatus(&status))
			return state;
		// 128: no system battery; 255: unknown
		state.HasBattery = status.BatteryFlag != 128 && status.BatteryFlag != 255;
		if (status.ACLineStatus != 255)
			state.OnAc = status.ACLineStatus == 1;
		if (status.BatteryLifePercent != 255)
			state.Percent = status.BatteryLifePercent;
		if (status.BatteryLifeTime != (DWORD)-1)
			state.SecondsLeft = status.BatteryLifeTime;
		state.Saver = status.SystemStatusFlag == 1;
		return state;
	}

	std::wstring BatteryMonitor::ChemistryText(std::wstring const& code) {
		static const struct {
			PCWSTR Code, Text;
		} names[] = {
			{ L"PbAc", L"Lead acid" }, { L"LION", L"Lithium-ion" }, { L"Li-I", L"Lithium-ion" }, { L"LiP", L"Lithium polymer" },
			{ L"NiCd", L"Nickel cadmium" }, { L"NiMH", L"Nickel metal hydride" }, { L"NiZn", L"Nickel zinc" },
			{ L"RAM", L"Rechargeable alkaline-manganese" },
		};
		for (auto& n : names)
			if (::_wcsicmp(n.Code, code.c_str()) == 0)
				return n.Text;
		return code;
	}

	std::wstring BatteryMonitor::StateText(uint32_t powerState) {
		std::wstring text = (powerState & BATTERY_CHARGING) ? L"Charging" : (powerState & BATTERY_DISCHARGING) ? L"Discharging"
			: (powerState & BATTERY_POWER_ON_LINE) ? L"On AC power" : L"Idle";
		if (powerState & BATTERY_CRITICAL)
			text += L", critical";
		return text;
	}

	float BatteryMonitor::TenthsKelvinToCelsius(uint32_t value) {
		return value / 10.0f - 273.15f;
	}
}
