#include "pch.h"
#include "ProcessorFrequency.h"
#include <pdh.h>
#include <pdhmsg.h>

#pragma comment(lib, "pdh")

using namespace WinSys;

namespace {
	// the instances are "<group>,<number>", besides "_Total" and "<group>,_Total"
	bool ParseInstance(PCWSTR name, uint32_t& group, uint32_t& number) {
		auto comma = ::wcschr(name, L',');
		if (!comma || !iswdigit(name[0]) || !iswdigit(comma[1]))
			return false;
		group = ::wcstoul(name, nullptr, 10);
		number = ::wcstoul(comma + 1, nullptr, 10);
		return true;
	}

	// the counter's value per instance, by its name; empty on failure
	bool ReadArray(PDH_HCOUNTER counter, std::vector<BYTE>& buffer, PDH_FMT_COUNTERVALUE_ITEM*& items, DWORD& count) {
		DWORD size = 0;
		count = 0;
		auto status = ::PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, nullptr);
		if (status != PDH_MORE_DATA)
			return false;
		buffer.resize(size);
		items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(buffer.data());
		return ::PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, items) == ERROR_SUCCESS;
	}
}

ProcessorFrequency::~ProcessorFrequency() {
	if (m_Query)
		::PdhCloseQuery(m_Query);
}

bool ProcessorFrequency::Open() {
	if (m_Query)
		return true;
	PDH_HQUERY query;
	auto status = ::PdhOpenQuery(nullptr, 0, &query);
	if (status != ERROR_SUCCESS) {
		::SetLastError(status);
		return false;
	}
	PDH_HCOUNTER performance = nullptr, frequency = nullptr;
	status = ::PdhAddEnglishCounter(query, L"\\Processor Information(*)\\% Processor Performance", 0, &performance);
	if (status == ERROR_SUCCESS)
		status = ::PdhAddEnglishCounter(query, L"\\Processor Information(*)\\Processor Frequency", 0, &frequency);
	if (status == ERROR_SUCCESS)
		// the first collection: the rate needs a previous one
		status = ::PdhCollectQueryData(query);
	if (status != ERROR_SUCCESS) {
		::PdhCloseQuery(query);
		::SetLastError(status);
		return false;
	}
	m_Query = query;
	m_Performance = performance;
	m_Frequency = frequency;

	// the groups' first indices, as the per-processor queries number the processors
	auto groups = ::GetActiveProcessorGroupCount();
	uint32_t start = 0;
	for (WORD group = 0; group < groups; group++) {
		m_GroupStart.push_back(start);
		start += ::GetActiveProcessorCount(group);
	}
	m_GroupStart.push_back(start);
	return true;
}

std::vector<float> ProcessorFrequency::Sample() {
	if (!m_Query || ::PdhCollectQueryData(m_Query) != ERROR_SUCCESS)
		return {};
	std::vector<BYTE> perfBuffer, freqBuffer;
	PDH_FMT_COUNTERVALUE_ITEM* perf, * freq;
	DWORD perfCount, freqCount;
	if (!ReadArray(m_Performance, perfBuffer, perf, perfCount) || !ReadArray(m_Frequency, freqBuffer, freq, freqCount))
		return {};

	std::vector<float> mhz(m_GroupStart.back());
	// the rated frequency by instance (the same order in both arrays isn't promised)
	for (DWORD i = 0; i < perfCount; i++) {
		uint32_t group, number;
		if (perf[i].FmtValue.CStatus != ERROR_SUCCESS || !ParseInstance(perf[i].szName, group, number)
			|| group + 1 >= m_GroupStart.size())
			continue;
		auto index = m_GroupStart[group] + number;
		if (index >= m_GroupStart[group + 1])
			continue;
		double rated = 0;
		if (i < freqCount && ::wcscmp(freq[i].szName, perf[i].szName) == 0)
			rated = freq[i].FmtValue.doubleValue;
		else
			for (DWORD j = 0; j < freqCount; j++)
				if (::wcscmp(freq[j].szName, perf[i].szName) == 0) {
					rated = freq[j].FmtValue.doubleValue;
					break;
				}
		mhz[index] = (float)(rated * perf[i].FmtValue.doubleValue / 100);
		if (index == 0)
			m_BaseMhz = (float)rated;
	}
	return mhz;
}
