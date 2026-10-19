#pragma once

#include <string>
#include <vector>
#include <cstdint>

//
// Network interface statistics from the IP Helper API (GetIfTable2).
// The header uses no IP Helper types, so consumers don't need winsock2.h/iphlpapi.h (which conflict with a full windows.h
// that was included first); the library links iphlpapi.lib itself.
//

namespace WinSys {
	enum class NetworkOperStatus : uint32_t {	// IF_OPER_STATUS
		Up = 1, Down, Testing, Unknown, Dormant, NotPresent, LowerLayerDown
	};

	struct NetworkInterface {
		uint64_t Luid;	// NET_LUID: stable while the interface exists, unlike the index
		uint32_t Index;
		uint32_t Type;	// IFTYPE (IF_TYPE_ETHERNET_CSMACD = 6, IF_TYPE_IEEE80211 = 71, IF_TYPE_SOFTWARE_LOOPBACK = 24...)
		std::wstring Alias;	// "Ethernet", "Wi-Fi"
		std::wstring Description;	// the adapter name
		NetworkOperStatus OperStatus;
		bool HardwareInterface;
		bool FilterInterface;	// a filter (LWF) module instance stacked on another interface; its counters duplicate the base
		bool ConnectorPresent;	// a physical connector
		bool Connected;	// media connected
		uint32_t PhysicalMedium;	// NDIS_PHYSICAL_MEDIUM: 0 (unspecified) for WAN miniports, virtual switches and tunnels
		uint64_t ReceiveLinkSpeed, TransmitLinkSpeed;	// bits per second
		uint64_t ReceivedBytes, SentBytes;
		uint64_t ReceivedPackets, SentPackets;	// unicast and non-unicast
		uint64_t ReceiveErrors, SendErrors;
		uint64_t ReceiveDiscards, SendDiscards;

		// A network adapter (physical, or a virtual NIC such as VMware's) that is present: not a filter, loopback, tunnel,
		// WAN miniport or virtual switch. Those have no physical medium, and their counters duplicate an adapter's.
		[[nodiscard]] bool IsAdapter() const;
	};

	struct NetworkInfo final {
		// Empty on failure
		[[nodiscard]] static std::vector<NetworkInterface> GetInterfaces();
	};

	//
	// Keeps the previous interface table and computes rates on each Update(). Rates are per second of real elapsed time,
	// so a late or skipped update doesn't distort them. An interface's rates are 0 on the update it first appears in.
	//
	class NetworkTracker {
	public:
		struct Interface : NetworkInterface {
			double ReceiveRate{ 0 }, SendRate{ 0 };	// bytes per second
			double ReceivePacketRate{ 0 }, SendPacketRate{ 0 };
		};

		// adaptersOnly: keep only interfaces for which NetworkInterface::IsAdapter() is true
		explicit NetworkTracker(bool adaptersOnly = true);

		// false if the query failed; the previous results are kept
		bool Update();

		[[nodiscard]] std::vector<Interface> const& GetInterfaces() const;
		[[nodiscard]] double GetTotalReceiveRate() const;
		[[nodiscard]] double GetTotalSendRate() const;

	private:
		std::vector<Interface> m_Interfaces;
		int64_t m_LastUpdate{ 0 };	// QPC
		double m_TotalReceive{ 0 }, m_TotalSend{ 0 };
		bool m_AdaptersOnly;
	};
}
