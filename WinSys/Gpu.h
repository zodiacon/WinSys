#pragma once

#include <vector>
#include <string>

namespace WinSys {
	//
	// GPU usage from the graphics kernel's statistics (D3DKMTQueryStatistics, as Task Manager and System Informer use):
	// an adapter has nodes (its engines: 3D, Copy, Video Decode...), whose running times give their utilization, and
	// memory segments, the aperture ones being shared (system) memory and the others dedicated. An adapter's
	// utilization is its busiest engine's, as Task Manager shows it.
	//
	struct GpuAdapter {
		LUID Luid;
		std::wstring Name;	// the description DXGI has for it
		std::vector<std::wstring> Engines;	// the distinct engine names, in node order
		std::vector<int> NodeEngine;	// a node's index in Engines
		std::vector<bool> ApertureSegments;	// by segment ID: shared memory
		uint64_t DedicatedLimit{ 0 }, SharedLimit{ 0 };	// bytes
	};

	// what's kept per process between GpuInfo::QueryProcess calls
	struct GpuProcessState {
		std::vector<int64_t> NodeTimes;	// every adapter's nodes, in order; empty: no previous sample
		int64_t Time{ 0 };
	};

	struct GpuProcessUsage {
		bool Known{ false };	// the process could be queried (and has a previous sample, for Usage)
		float Usage{ 0 };	// percent: the busiest engine of all adapters
		uint64_t Dedicated{ 0 }, Shared{ 0 };	// bytes committed
	};

	struct GpuInfo final {
		// the adapters that render (no software ones), read once
		[[nodiscard]] static std::vector<GpuAdapter> const& GetAdapters();

		// a process's usage since the last call with the same state. The handle needs PROCESS_QUERY_INFORMATION (a
		// limited one gets STATUS_INVALID_PARAMETER). A process without GPU memory isn't queried for its engines (most
		// processes: a call per engine is the cost)
		static GpuProcessUsage QueryProcess(HANDLE hProcess, GpuProcessState& state);
	};

	//
	// The whole system's GPU usage, sampled on every Update.
	//
	class GpuTracker {
	public:
		struct AdapterSample {
			std::vector<float> Engines;	// percent, in GpuAdapter::Engines order (the busiest node of each)
			float Usage{ 0 };	// the busiest engine
			uint64_t DedicatedUsed{ 0 }, SharedUsed{ 0 };	// bytes resident
		};

		// false until there's a previous sample to compute the rates from
		bool Update();
		// in GpuInfo::GetAdapters order
		[[nodiscard]] std::vector<AdapterSample> const& GetSamples() const;

	private:
		std::vector<std::vector<int64_t>> m_PrevTimes;	// per adapter, per node: running time
		int64_t m_PrevTime{ 0 };	// 100 ns units
		std::vector<AdapterSample> m_Samples;
	};
}
