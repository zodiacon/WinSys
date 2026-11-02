#include "pch.h"
#include "ThermalZones.h"
#include <pdh.h>
#include <pdhmsg.h>
#include <algorithm>

#pragma comment(lib, "pdh")

namespace WinSys {
	namespace {
		// the counter's values by instance; false on failure (no instances included)
		bool ReadArray(PDH_HCOUNTER counter, std::vector<BYTE>& buffer, PDH_FMT_COUNTERVALUE_ITEM*& items, DWORD& count) {
			DWORD size = 0;
			count = 0;
			if (::PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, nullptr) != PDH_MORE_DATA)
				return false;
			buffer.resize(size);
			items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(buffer.data());
			return ::PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, items) == ERROR_SUCCESS;
		}
	}

	ThermalZoneMonitor::~ThermalZoneMonitor() {
		if (m_Query)
			::PdhCloseQuery(m_Query);
	}

	float ThermalZoneMonitor::ToCelsius(double value, bool highPrecision) {
		return (float)((highPrecision ? value / 10.0 : value) - 273.15);
	}

	bool ThermalZoneMonitor::Open() {
		if (m_Query)
			return true;
		// the high precision counter first (Windows 10 and later), else the whole-Kelvin one
		for (auto [path, high] : { std::pair{ L"\\Thermal Zone Information(*)\\High Precision Temperature", true },
			std::pair{ L"\\Thermal Zone Information(*)\\Temperature", false } }) {
			PDH_HQUERY query = nullptr;
			auto status = ::PdhOpenQuery(nullptr, 0, &query);
			if (status != ERROR_SUCCESS) {
				::SetLastError(status);
				return false;
			}
			PDH_HCOUNTER counter = nullptr;
			status = ::PdhAddEnglishCounter(query, path, 0, &counter);
			if (status == ERROR_SUCCESS)
				status = ::PdhCollectQueryData(query);
			std::vector<BYTE> buffer;
			PDH_FMT_COUNTERVALUE_ITEM* items = nullptr;
			DWORD count = 0;
			if (status == ERROR_SUCCESS && ReadArray(counter, buffer, items, count) && count > 0) {
				m_Query = query;
				m_Counter = counter;
				m_HighPrecision = high;
				return true;
			}
			::PdhCloseQuery(query);
		}
		::SetLastError(ERROR_NOT_FOUND);
		return false;
	}

	std::vector<ThermalZone> ThermalZoneMonitor::Read() {
		std::vector<ThermalZone> zones;
		if (!m_Query || ::PdhCollectQueryData(m_Query) != ERROR_SUCCESS)
			return zones;
		std::vector<BYTE> buffer;
		PDH_FMT_COUNTERVALUE_ITEM* items = nullptr;
		DWORD count = 0;
		if (!ReadArray(m_Counter, buffer, items, count))
			return zones;
		for (DWORD i = 0; i < count; i++) {
			// a zone that reports nothing (0 K) isn't a temperature
			if (items[i].FmtValue.CStatus != ERROR_SUCCESS || items[i].FmtValue.doubleValue <= 0)
				continue;
			zones.push_back({ items[i].szName, ToCelsius(items[i].FmtValue.doubleValue, m_HighPrecision) });
		}
		std::sort(zones.begin(), zones.end(), [](auto& a, auto& b) { return a.Name < b.Name; });
		return zones;
	}
}
