#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// The IP stack's tables, read-only, as plain text (the header uses no IP Helper types; see Network.h):
// - the neighbors (the ARP cache for IPv4, the neighbor cache for IPv6): GetIpNetTable2
// - the routes, IPv4 and IPv6: GetIpForwardTable2, with each interface's metric (GetIpInterfaceEntry), which Windows
//   adds to the route's own to choose among them
// - the DNS client's cache, from WMI's MSFT_DNSClientCache (as PowerShell's Get-DnsClientCache; the caller initializes
//   COM), so nothing goes to the network. dnsapi's DnsGetCacheDataTable, which older tools used, returns nothing on
//   current Windows (whose ipconfig moved to an undocumented successor). FlushDnsCache empties the cache, as
//   ipconfig /flushdns (DnsFlushResolverCache, which ipconfig imports, resolved at run time)
// No elevation needed for any.
//

namespace WinSys {
	struct NeighborEntry {
		std::wstring Address;			// IPv4 or IPv6
		std::wstring PhysicalAddress;	// "00-11-22-33-44-55"; empty if none (yet)
		std::wstring Interface;			// its alias ("Ethernet")
		std::wstring State;				// "Reachable", "Stale", "Permanent"...
		bool Ipv6{ false };
		bool IsRouter{ false };
	};

	struct RouteEntry {
		std::wstring Destination;	// "10.0.0.0/8", "::/0"
		std::wstring NextHop;		// "0.0.0.0" or "::": on-link
		std::wstring Interface;
		std::wstring Protocol;		// "Local", "Network Management", "DHCP"... (NL_ROUTE_PROTOCOL)
		uint32_t Metric{ 0 };
		uint32_t InterfaceMetric{ 0 };	// added to Metric for the route's effective metric
		bool Ipv6{ false };
	};

	struct DnsCacheRecord {
		std::wstring Name;	// the name queried
		std::wstring Type;	// "A", "AAAA", "CNAME"...
		std::wstring Data;	// an address, a name, text; empty for a negative entry (the name doesn't exist)
		uint32_t Ttl{ 0 };	// seconds left
		std::wstring Section;	// "Answer", "Additional"...
	};

	struct NetworkTables final {
		// nothing (with the last error set) if the table can't be read
		[[nodiscard]] static std::optional<std::vector<NeighborEntry>> ReadNeighbors();
		[[nodiscard]] static std::optional<std::vector<RouteEntry>> ReadRoutes();
		[[nodiscard]] static std::optional<std::vector<DnsCacheRecord>> ReadDnsCache();
		static bool FlushDnsCache();
	};
}
