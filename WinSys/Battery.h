#pragma once

#include <vector>
#include <string>
#include <optional>
#include <wil/resource.h>

namespace WinSys {
	// what the battery driver reports (BATTERY_STATUS and the other queries), with "unknown" made explicit
	struct BatteryReading {
		// PowerState's bits (poclass.h's BATTERY_POWER_ON_LINE, BATTERY_DISCHARGING, BATTERY_CHARGING, BATTERY_CRITICAL)
		static constexpr uint32_t OnLine = 1, Discharging = 2, Charging = 4, Critical = 8;
		uint32_t PowerState{ 0 };	// BATTERY_POWER_ON_LINE, BATTERY_DISCHARGING, BATTERY_CHARGING, BATTERY_CRITICAL
		std::optional<uint32_t> Capacity;	// remaining, in mWh (or relative units: BatteryInfo::Relative)
		std::optional<uint32_t> Voltage;	// mV
		std::optional<int32_t> Rate;		// mW; negative while discharging
		std::optional<uint32_t> EstimatedSeconds;	// to empty while discharging (the driver's estimate)
		std::optional<float> TemperatureC;	// the battery's own sensor, rarely reported
	};

	struct BatteryInfo {
		std::wstring DevicePath;
		std::wstring Name, Manufacturer;	// may be empty
		std::wstring Chemistry;		// "LION", "LiP"..., as the driver reports
		bool Rechargeable{ true };
		bool Relative{ false };		// capacities are relative units, not mWh (BATTERY_CAPACITY_RELATIVE)
		std::optional<uint32_t> DesignedCapacity, FullChargedCapacity;
		uint32_t CycleCount{ 0 };	// 0 if not reported
		BatteryReading Reading;
		bool HasReading{ false };	// the status query succeeded

		// the charge in percent of the full charge; nothing if a capacity isn't known
		[[nodiscard]] std::optional<float> ChargePercent() const;
		// the full charge as a share of the design capacity (the battery's wear); nothing if not known
		[[nodiscard]] std::optional<float> HealthPercent() const;
	};

	// GetSystemPowerStatus, for the whole system
	struct SystemPowerState {
		bool HasBattery{ false };
		std::optional<bool> OnAc;			// nothing if unknown
		std::optional<uint8_t> Percent;		// all batteries together
		std::optional<uint32_t> SecondsLeft;	// on battery
		bool Saver{ false };				// battery saver is on
	};

	//
	// The system's batteries, through the battery class driver (the GUID_DEVICE_BATTERY interfaces, opened once by
	// Open: IOCTL_BATTERY_QUERY_TAG, then IOCTL_BATTERY_QUERY_INFORMATION for the static information and
	// IOCTL_BATTERY_QUERY_STATUS, the estimated time and the temperature on every Read). No elevation needed. A desktop
	// has none (Open returns 0); a removed or replaced battery gets a new tag, which Read asks for again.
	//
	class BatteryMonitor {
	public:
		// finds and opens the batteries; how many
		size_t Open();
		[[nodiscard]] size_t GetCount() const {
			return m_Batteries.size();
		}
		// each battery's reading now (HasReading false for one that didn't answer)
		std::vector<BatteryInfo> Read();

		[[nodiscard]] static SystemPowerState GetSystemState();

		// "Lithium-ion" for "LION" and the other ACPI chemistry codes; else the code
		[[nodiscard]] static std::wstring ChemistryText(std::wstring const& code);
		// "Charging", "Discharging", "On AC power" (full or not charging), with ", critical"
		[[nodiscard]] static std::wstring StateText(uint32_t powerState);
		// the battery class driver's tenths of a Kelvin, in Celsius
		[[nodiscard]] static float TenthsKelvinToCelsius(uint32_t value);

	private:
		struct Device {
			wil::unique_hfile Handle;
			ULONG Tag{ 0 };
			BatteryInfo Info;
		};
		// the battery's current tag (0: none in the slot) and, for a new tag, its static information
		bool RefreshTag(Device& device);

		std::vector<Device> m_Batteries;
	};
}
