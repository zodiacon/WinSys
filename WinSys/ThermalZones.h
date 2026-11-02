#pragma once

#include <vector>
#include <string>

namespace WinSys {
	struct ThermalZone {
		std::wstring Name;	// the ACPI zone's instance name ("\_TZ.TZ00", "\_TZ.CPUZ")
		float Celsius{ 0 };
	};

	//
	// The ACPI thermal zones' temperatures, from the "Thermal Zone Information" performance counters (PDH; no elevation
	// needed): "High Precision Temperature" (tenths of a Kelvin) where it's there, else "Temperature" (Kelvin). Many
	// desktops have no ACPI thermal zone (and their CPU's own sensor needs a vendor's driver); laptops usually do.
	//
	class ThermalZoneMonitor {
	public:
		ThermalZoneMonitor() = default;
		ThermalZoneMonitor(ThermalZoneMonitor const&) = delete;
		ThermalZoneMonitor& operator=(ThermalZoneMonitor const&) = delete;
		~ThermalZoneMonitor();

		// false if the counters can't be read or there's no zone (with the last error)
		bool Open();
		// the zones now, by name; empty on failure
		std::vector<ThermalZone> Read();

		// a counter value in Celsius: tenths of a Kelvin for High Precision Temperature, else Kelvin
		[[nodiscard]] static float ToCelsius(double value, bool highPrecision);

	private:
		void* m_Query{ nullptr };	// PDH_HQUERY
		void* m_Counter{ nullptr };	// PDH_HCOUNTER
		bool m_HighPrecision{ false };
	};
}
