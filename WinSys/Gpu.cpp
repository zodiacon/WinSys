#include "pch.h"
#include "Gpu.h"
#include <d3dkmthk.h>
#include <dxgi.h>
#include <wil/com.h>
#include <algorithm>

#pragma comment(lib, "gdi32")
#pragma comment(lib, "dxgi")

namespace {
	// running times are in 100 ns units (the header says microseconds, but the deltas agree with 100 ns)
	int64_t Now() {
		static const int64_t frequency = [] { LARGE_INTEGER f; ::QueryPerformanceFrequency(&f); return f.QuadPart; }();
		LARGE_INTEGER counter;
		::QueryPerformanceCounter(&counter);
		return (int64_t)((double)counter.QuadPart * 10000000 / frequency);
	}

	PCWSTR EngineTypeName(DXGK_ENGINE_TYPE type) {
		switch (type) {
			case DXGK_ENGINE_TYPE_3D: return L"3D";
			case DXGK_ENGINE_TYPE_VIDEO_DECODE: return L"Video Decode";
			case DXGK_ENGINE_TYPE_VIDEO_ENCODE: return L"Video Encode";
			case DXGK_ENGINE_TYPE_VIDEO_PROCESSING: return L"Video Processing";
			case DXGK_ENGINE_TYPE_SCENE_ASSEMBLY: return L"Scene Assembly";
			case DXGK_ENGINE_TYPE_COPY: return L"Copy";
			case DXGK_ENGINE_TYPE_OVERLAY: return L"Overlay";
			case DXGK_ENGINE_TYPE_CRYPTO: return L"Crypto";
			case DXGK_ENGINE_TYPE_VIDEO_CODEC: return L"Video Codec";
		}
		return L"Other";
	}

	bool Query(D3DKMT_QUERYSTATISTICS& query) {
		return NT_SUCCESS(::D3DKMTQueryStatistics(&query));
	}

	// the adapter's description, by LUID
	std::wstring GetAdapterName(LUID luid) {
		wil::com_ptr_nothrow<IDXGIFactory1> factory;
		if (FAILED(::CreateDXGIFactory1(IID_PPV_ARGS(&factory))))
			return L"";
		for (UINT i = 0; ; i++) {
			wil::com_ptr_nothrow<IDXGIAdapter1> adapter;
			if (factory->EnumAdapters1(i, &adapter) == DXGI_ERROR_NOT_FOUND)
				break;
			DXGI_ADAPTER_DESC1 desc;
			if (SUCCEEDED(adapter->GetDesc1(&desc)) && desc.AdapterLuid.LowPart == luid.LowPart && desc.AdapterLuid.HighPart == luid.HighPart)
				return desc.Description;
		}
		return L"";
	}

	std::vector<WinSys::GpuAdapter> LoadAdapters() {
		std::vector<WinSys::GpuAdapter> adapters;
		D3DKMT_ENUMADAPTERS2 enumAdapters{};
		if (!NT_SUCCESS(::D3DKMTEnumAdapters2(&enumAdapters)) || enumAdapters.NumAdapters == 0)
			return adapters;
		std::vector<D3DKMT_ADAPTERINFO> infos(enumAdapters.NumAdapters);
		enumAdapters.pAdapters = infos.data();
		if (!NT_SUCCESS(::D3DKMTEnumAdapters2(&enumAdapters)))
			return adapters;
		infos.resize(enumAdapters.NumAdapters);

		for (auto& info : infos) {
			// the closing goes with the handle, whichever way the loop continues
			auto close = wil::scope_exit([&] { D3DKMT_CLOSEADAPTER c{ info.hAdapter }; ::D3DKMTCloseAdapter(&c); });

			D3DKMT_ADAPTERTYPE type{};
			D3DKMT_QUERYADAPTERINFO queryType{ info.hAdapter, KMTQAITYPE_ADAPTERTYPE, &type, sizeof(type) };
			if (!NT_SUCCESS(::D3DKMTQueryAdapterInfo(&queryType)) || type.SoftwareDevice || !type.RenderSupported)
				continue;

			D3DKMT_QUERYSTATISTICS query{};
			query.Type = D3DKMT_QUERYSTATISTICS_ADAPTER;
			query.AdapterLuid = info.AdapterLuid;
			if (!Query(query) || query.QueryResult.AdapterInformation.NodeCount == 0)
				continue;
			auto nodes = query.QueryResult.AdapterInformation.NodeCount;
			auto segments = query.QueryResult.AdapterInformation.NbSegments;

			WinSys::GpuAdapter adapter;
			adapter.Luid = info.AdapterLuid;
			adapter.Name = GetAdapterName(info.AdapterLuid);
			for (ULONG node = 0; node < nodes; node++) {
				// the engine's name: the driver's, else its type's
				D3DKMT_NODEMETADATA meta{};
				meta.NodeOrdinalAndAdapterIndex = node;
				D3DKMT_QUERYADAPTERINFO queryMeta{ info.hAdapter, KMTQAITYPE_NODEMETADATA, &meta, sizeof(meta) };
				std::wstring name = NT_SUCCESS(::D3DKMTQueryAdapterInfo(&queryMeta))
					? (meta.NodeData.FriendlyName[0] ? meta.NodeData.FriendlyName : EngineTypeName(meta.NodeData.EngineType))
					: L"Engine " + std::to_wstring(node);
				auto it = std::ranges::find(adapter.Engines, name);
				if (it == adapter.Engines.end())
					it = adapter.Engines.insert(adapter.Engines.end(), name);
				adapter.NodeEngine.push_back((int)(it - adapter.Engines.begin()));
			}
			for (ULONG segment = 0; segment < segments; segment++) {
				D3DKMT_QUERYSTATISTICS querySegment{};
				querySegment.Type = D3DKMT_QUERYSTATISTICS_SEGMENT;
				querySegment.AdapterLuid = info.AdapterLuid;
				querySegment.QuerySegment.SegmentId = segment;
				bool aperture = false;
				if (Query(querySegment)) {
					auto& s = querySegment.QueryResult.SegmentInformation;
					aperture = s.Aperture != 0;
					(aperture ? adapter.SharedLimit : adapter.DedicatedLimit) += s.CommitLimit;
				}
				adapter.ApertureSegments.push_back(aperture);
			}
			if (adapter.Name.empty())
				adapter.Name = L"GPU " + std::to_wstring(adapters.size());
			adapters.push_back(std::move(adapter));
		}
		return adapters;
	}
}

namespace {
	std::vector<WinSys::GpuAdapter>& Adapters() {
		static std::vector<WinSys::GpuAdapter> adapters = LoadAdapters();
		return adapters;
	}

	// a device restarted gets a new LUID: each adapter takes the one of the same name and shape, which keeps the list
	// (and its users' indices) as it was
	void RemapLuids() {
		auto fresh = LoadAdapters();
		std::vector<bool> used(fresh.size());
		for (auto& adapter : Adapters())
			for (size_t i = 0; i < fresh.size(); i++)
				if (!used[i] && fresh[i].Name == adapter.Name && fresh[i].NodeEngine.size() == adapter.NodeEngine.size()
					&& fresh[i].ApertureSegments.size() == adapter.ApertureSegments.size()) {
					adapter.Luid = fresh[i].Luid;
					used[i] = true;
					break;
				}
	}
}

namespace WinSys {
	std::vector<GpuAdapter> const& GpuInfo::GetAdapters() {
		return Adapters();
	}

	bool GpuTracker::Update() {
		auto& adapters = GpuInfo::GetAdapters();
		auto now = Now();
		auto elapsed = m_PrevTime ? now - m_PrevTime : 0;
		bool first = m_PrevTimes.size() != adapters.size();
		if (first)
			m_PrevTimes.assign(adapters.size(), {});
		m_Samples.assign(adapters.size(), {});
		bool stale = false;	// an adapter none of whose nodes could be queried: its LUID may have changed

		for (size_t a = 0; a < adapters.size(); a++) {
			auto& adapter = adapters[a];
			auto& sample = m_Samples[a];
			auto& prev = m_PrevTimes[a];
			sample.Engines.assign(adapter.Engines.size(), 0);
			// -1: not queried, so the next delta doesn't start from 0 (a whole lifetime's running time: 100%)
			std::vector<int64_t> times(adapter.NodeEngine.size(), -1);
			bool queried = false;
			for (size_t node = 0; node < times.size(); node++) {
				D3DKMT_QUERYSTATISTICS query{};
				query.Type = D3DKMT_QUERYSTATISTICS_NODE;
				query.AdapterLuid = adapter.Luid;
				query.QueryNode.NodeId = (ULONG)node;
				if (!Query(query))
					continue;
				queried = true;
				times[node] = query.QueryResult.NodeInformation.GlobalInformation.RunningTime.QuadPart;
				if (elapsed > 0 && prev.size() == times.size() && prev[node] >= 0) {
					auto busy = std::clamp(100.0f * (times[node] - prev[node]) / elapsed, 0.0f, 100.0f);
					auto& engine = sample.Engines[adapter.NodeEngine[node]];
					engine = (std::max)(engine, busy);
				}
			}
			if (!queried && !times.empty())
				stale = true;
			prev = std::move(times);
			sample.Usage = sample.Engines.empty() ? 0 : *std::ranges::max_element(sample.Engines);

			for (size_t segment = 0; segment < adapter.ApertureSegments.size(); segment++) {
				D3DKMT_QUERYSTATISTICS query{};
				query.Type = D3DKMT_QUERYSTATISTICS_SEGMENT;
				query.AdapterLuid = adapter.Luid;
				query.QuerySegment.SegmentId = (ULONG)segment;
				if (Query(query))
					(adapter.ApertureSegments[segment] ? sample.SharedUsed : sample.DedicatedUsed) += query.QueryResult.SegmentInformation.BytesResident;
			}
		}
		// not often: it enumerates the adapters (DXGI), and an adapter that's gone (an external GPU) stays stale
		if (auto tick = ::GetTickCount64(); stale && tick - m_RemapTime >= 10000) {
			m_RemapTime = tick;
			RemapLuids();
		}
		bool valid = !first && elapsed > 0;
		m_PrevTime = now;
		return valid;
	}

	std::vector<GpuTracker::AdapterSample> const& GpuTracker::GetSamples() const {
		return m_Samples;
	}

	GpuProcessUsage GpuInfo::QueryProcess(HANDLE hProcess, GpuProcessState& state) {
		GpuProcessUsage usage;
		auto& adapters = GetAdapters();
		if (!hProcess || adapters.empty())
			return usage;

		for (auto& adapter : adapters) {
			for (size_t segment = 0; segment < adapter.ApertureSegments.size(); segment++) {
				D3DKMT_QUERYSTATISTICS query{};
				query.Type = D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT;
				query.AdapterLuid = adapter.Luid;
				query.hProcess = hProcess;
				query.QueryProcessSegment.SegmentId = (ULONG)segment;
				if (!Query(query))
					continue;
				usage.Known = true;
				(adapter.ApertureSegments[segment] ? usage.Shared : usage.Dedicated) += query.QueryResult.ProcessSegmentInformation.BytesCommitted;
			}
		}
		if (!usage.Known)
			return usage;
		if (usage.Dedicated == 0 && usage.Shared == 0) {
			// no GPU memory, no GPU work: the engines aren't queried, and the next sample starts over
			state.NodeTimes.clear();
			return usage;
		}

		auto now = Now();
		std::vector<int64_t> times;
		for (auto& adapter : adapters) {
			for (size_t node = 0; node < adapter.NodeEngine.size(); node++) {
				D3DKMT_QUERYSTATISTICS query{};
				query.Type = D3DKMT_QUERYSTATISTICS_PROCESS_NODE;
				query.AdapterLuid = adapter.Luid;
				query.hProcess = hProcess;
				query.QueryProcessNode.NodeId = (ULONG)node;
				// -1: not queried (see GpuTracker::Update)
				times.push_back(Query(query) ? query.QueryResult.ProcessNodeInformation.RunningTime.QuadPart : -1);
			}
		}
		auto elapsed = now - state.Time;
		if (state.NodeTimes.size() == times.size() && elapsed > 0)
			for (size_t i = 0; i < times.size(); i++)
				if (times[i] >= 0 && state.NodeTimes[i] >= 0)
					usage.Usage = (std::max)(usage.Usage, std::clamp(100.0f * (times[i] - state.NodeTimes[i]) / elapsed, 0.0f, 100.0f));
		state.NodeTimes = std::move(times);
		state.Time = now;
		return usage;
	}
}
