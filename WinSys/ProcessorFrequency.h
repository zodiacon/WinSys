#pragma once

#include <cstdint>
#include <vector>

//
// The logical processors' actual frequencies, as Task Manager's Speed: the Processor Information performance
// counters' Processor Frequency (the rated one, MHz) times % Processor Performance (above 100 when boosting), through
// PDH with the counters' English names (any display language). The rated frequency alone (CallNtPowerInformation's
// CurrentMhz) doesn't move. % Processor Performance is a rate, so the first Sample has nothing.
//
namespace WinSys {
	class ProcessorFrequency {
	public:
		ProcessorFrequency() = default;
		ProcessorFrequency(ProcessorFrequency const&) = delete;
		ProcessorFrequency& operator=(ProcessorFrequency const&) = delete;
		~ProcessorFrequency();

		// false (with a PDH status as the last error) if the counters can't be opened
		bool Open();
		[[nodiscard]] bool IsOpen() const {
			return m_Query != nullptr;
		}
		// MHz per logical processor, across all processor groups in group order (as SystemInfo's per-processor
		// queries, group by group); empty on the first call or a failure
		[[nodiscard]] std::vector<float> Sample();
		// the rated frequency (MHz) of the last Sample's first processor; 0 if none
		[[nodiscard]] float GetBaseMhz() const {
			return m_BaseMhz;
		}

	private:
		void* m_Query{ nullptr };	// PDH_HQUERY
		void* m_Performance{ nullptr };	// PDH_HCOUNTER: % Processor Performance
		void* m_Frequency{ nullptr };	// Processor Frequency
		std::vector<uint32_t> m_GroupStart;	// each group's first index
		float m_BaseMhz{ 0 };
	};
}
