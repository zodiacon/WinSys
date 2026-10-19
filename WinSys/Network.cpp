#include "pch.h"
// phnt_windows.h includes windows.h lean, so winsock2.h can still come after it
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include "Network.h"

#pragma comment(lib, "iphlpapi")

using namespace WinSys;

bool NetworkInterface::IsAdapter() const {
	return !FilterInterface && Type != IF_TYPE_SOFTWARE_LOOPBACK && PhysicalMedium != NdisPhysicalMediumUnspecified
		&& OperStatus != NetworkOperStatus::NotPresent;
}

std::vector<NetworkInterface> NetworkInfo::GetInterfaces() {
	std::vector<NetworkInterface> interfaces;
	PMIB_IF_TABLE2 table;
	if (::GetIfTable2(&table) != NO_ERROR)
		return interfaces;

	interfaces.reserve(table->NumEntries);
	for (ULONG i = 0; i < table->NumEntries; i++) {
		auto& row = table->Table[i];
		NetworkInterface ni;
		ni.Luid = row.InterfaceLuid.Value;
		ni.Index = row.InterfaceIndex;
		ni.Type = row.Type;
		ni.Alias = row.Alias;
		ni.Description = row.Description;
		ni.OperStatus = (NetworkOperStatus)row.OperStatus;
		ni.HardwareInterface = row.InterfaceAndOperStatusFlags.HardwareInterface;
		ni.FilterInterface = row.InterfaceAndOperStatusFlags.FilterInterface;
		ni.ConnectorPresent = row.InterfaceAndOperStatusFlags.ConnectorPresent;
		ni.Connected = row.MediaConnectState == MediaConnectStateConnected;
		ni.PhysicalMedium = row.PhysicalMediumType;
		ni.ReceiveLinkSpeed = row.ReceiveLinkSpeed;
		ni.TransmitLinkSpeed = row.TransmitLinkSpeed;
		ni.ReceivedBytes = row.InOctets;
		ni.SentBytes = row.OutOctets;
		ni.ReceivedPackets = row.InUcastPkts + row.InNUcastPkts;
		ni.SentPackets = row.OutUcastPkts + row.OutNUcastPkts;
		ni.ReceiveErrors = row.InErrors;
		ni.SendErrors = row.OutErrors;
		ni.ReceiveDiscards = row.InDiscards;
		ni.SendDiscards = row.OutDiscards;
		interfaces.push_back(std::move(ni));
	}
	::FreeMibTable(table);
	return interfaces;
}

NetworkTracker::NetworkTracker(bool adaptersOnly) : m_AdaptersOnly(adaptersOnly) {
}

bool NetworkTracker::Update() {
	auto current = NetworkInfo::GetInterfaces();
	if (current.empty())
		return false;

	LARGE_INTEGER now, frequency;
	::QueryPerformanceCounter(&now);
	::QueryPerformanceFrequency(&frequency);
	double seconds = m_LastUpdate ? double(now.QuadPart - m_LastUpdate) / frequency.QuadPart : 0;
	m_LastUpdate = now.QuadPart;

	// counters can go backwards (an adapter reset clears them); count that as no traffic
	auto rate = [=](uint64_t now, uint64_t before) {
		return seconds > 0 && now >= before ? (now - before) / seconds : 0.0;
	};

	std::vector<Interface> interfaces;
	interfaces.reserve(current.size());
	m_TotalReceive = m_TotalSend = 0;
	for (auto& ni : current) {
		if (m_AdaptersOnly && !ni.IsAdapter())
			continue;
		Interface item;
		static_cast<NetworkInterface&>(item) = std::move(ni);
		// the table is short (a handful of adapters), so a linear search is fine
		auto prev = std::find_if(m_Interfaces.begin(), m_Interfaces.end(), [&](auto& i) { return i.Luid == item.Luid; });
		if (prev != m_Interfaces.end()) {
			item.ReceiveRate = rate(item.ReceivedBytes, prev->ReceivedBytes);
			item.SendRate = rate(item.SentBytes, prev->SentBytes);
			item.ReceivePacketRate = rate(item.ReceivedPackets, prev->ReceivedPackets);
			item.SendPacketRate = rate(item.SentPackets, prev->SentPackets);
		}
		m_TotalReceive += item.ReceiveRate;
		m_TotalSend += item.SendRate;
		interfaces.push_back(std::move(item));
	}
	m_Interfaces = std::move(interfaces);
	return true;
}

std::vector<NetworkTracker::Interface> const& NetworkTracker::GetInterfaces() const {
	return m_Interfaces;
}

double NetworkTracker::GetTotalReceiveRate() const {
	return m_TotalReceive;
}

double NetworkTracker::GetTotalSendRate() const {
	return m_TotalSend;
}
