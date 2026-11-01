#include "pch.h"
#include "NetworkTables.h"
// as Connections.cpp: ws2ipdef.h needs winsock2.h (the lean windows.h leaves winsock.h out, so no clash)
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <wbemidl.h>
#include <wil/com.h>
#include <wil/resource.h>
#include <unordered_map>

#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "wbemuuid")

using namespace WinSys;

namespace {
	std::wstring AddressText(SOCKADDR_INET const& address) {
		WCHAR text[INET6_ADDRSTRLEN]{};
		if (address.si_family == AF_INET)
			::InetNtopW(AF_INET, &address.Ipv4.sin_addr, text, _countof(text));
		else if (address.si_family == AF_INET6)
			::InetNtopW(AF_INET6, &address.Ipv6.sin6_addr, text, _countof(text));
		return text;
	}

	// interfaces' aliases by index, looked up once per read
	class InterfaceNames {
	public:
		std::wstring const& Get(NET_IFINDEX index) {
			auto it = m_Names.find(index);
			if (it != m_Names.end())
				return it->second;
			std::wstring name;
			NET_LUID luid;
			WCHAR alias[NDIS_IF_MAX_STRING_SIZE + 1];
			if (::ConvertInterfaceIndexToLuid(index, &luid) == NO_ERROR && ::ConvertInterfaceLuidToAlias(&luid, alias, _countof(alias)) == NO_ERROR)
				name = alias;
			else
				name = L"Interface " + std::to_wstring(index);
			return m_Names.emplace(index, std::move(name)).first->second;
		}

	private:
		std::unordered_map<NET_IFINDEX, std::wstring> m_Names;
	};

	PCWSTR NeighborStateName(NL_NEIGHBOR_STATE state) {
		switch (state) {
			case NlnsUnreachable: return L"Unreachable";
			case NlnsIncomplete: return L"Incomplete";
			case NlnsProbe: return L"Probe";
			case NlnsDelay: return L"Delay";
			case NlnsStale: return L"Stale";
			case NlnsReachable: return L"Reachable";
			case NlnsPermanent: return L"Permanent";
		}
		return L"";
	}

	PCWSTR RouteProtocolName(NL_ROUTE_PROTOCOL protocol) {
		switch ((int)protocol) {
			case MIB_IPPROTO_OTHER: return L"Other";
			case MIB_IPPROTO_LOCAL: return L"Local";
			case MIB_IPPROTO_NETMGMT: return L"Network Management";
			case MIB_IPPROTO_ICMP: return L"ICMP";
			case MIB_IPPROTO_RIP: return L"RIP";
			case MIB_IPPROTO_OSPF: return L"OSPF";
			case MIB_IPPROTO_BGP: return L"BGP";
			case MIB_IPPROTO_DHCP: return L"DHCP";
			case MIB_IPPROTO_NT_AUTOSTATIC: return L"Auto Static";
			case MIB_IPPROTO_NT_STATIC: return L"Static";
			case MIB_IPPROTO_NT_STATIC_NON_DOD: return L"Static (non-DOD)";
		}
		return L"Other";
	}

	bool SetError(DWORD error) {
		::SetLastError(error);
		return false;
	}

	FARPROC DnsApi(PCSTR name) {
		// nothing imports it, so it's loaded (once: the handle stays, as the process may use it again)
		static auto module = ::LoadLibraryExW(L"dnsapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
		return module ? ::GetProcAddress(module, name) : nullptr;
	}

	std::wstring DnsTypeName(WORD type) {
		switch (type) {
			case DNS_TYPE_A: return L"A";
			case DNS_TYPE_NS: return L"NS";
			case DNS_TYPE_CNAME: return L"CNAME";
			case DNS_TYPE_SOA: return L"SOA";
			case DNS_TYPE_PTR: return L"PTR";
			case DNS_TYPE_MX: return L"MX";
			case DNS_TYPE_TEXT: return L"TXT";
			case DNS_TYPE_AAAA: return L"AAAA";
			case DNS_TYPE_SRV: return L"SRV";
			case 64: return L"SVCB";
			case 65: return L"HTTPS";
		}
		return L"TYPE" + std::to_wstring(type);
	}

	PCWSTR DnsSectionName(DWORD section) {
		switch (section) {
			case DnsSectionQuestion: return L"Question";
			case DnsSectionAnswer: return L"Answer";
			case DnsSectionAuthority: return L"Authority";
			case DnsSectionAddtional: return L"Additional";
		}
		return L"";
	}

}

std::optional<std::vector<NeighborEntry>> NetworkTables::ReadNeighbors() {
	PMIB_IPNET_TABLE2 table = nullptr;
	if (auto error = ::GetIpNetTable2(AF_UNSPEC, &table); error != NO_ERROR) {
		::SetLastError(error);
		return std::nullopt;
	}
	InterfaceNames names;
	std::vector<NeighborEntry> entries;
	entries.reserve(table->NumEntries);
	for (ULONG i = 0; i < table->NumEntries; i++) {
		auto& row = table->Table[i];
		NeighborEntry e;
		e.Address = AddressText(row.Address);
		e.Ipv6 = row.Address.si_family == AF_INET6;
		for (ULONG b = 0; b < row.PhysicalAddressLength; b++) {
			WCHAR hex[4];
			swprintf_s(hex, b ? L"-%02X" : L"%02X", row.PhysicalAddress[b]);
			e.PhysicalAddress += hex;
		}
		e.Interface = names.Get(row.InterfaceIndex);
		e.State = NeighborStateName(row.State);
		e.IsRouter = row.IsRouter != FALSE;
		entries.push_back(std::move(e));
	}
	::FreeMibTable(table);
	return entries;
}

std::optional<std::vector<RouteEntry>> NetworkTables::ReadRoutes() {
	PMIB_IPFORWARD_TABLE2 table = nullptr;
	if (auto error = ::GetIpForwardTable2(AF_UNSPEC, &table); error != NO_ERROR) {
		::SetLastError(error);
		return std::nullopt;
	}
	InterfaceNames names;
	// the interfaces' metrics, by family and index
	std::unordered_map<uint64_t, ULONG> metrics;
	std::vector<RouteEntry> entries;
	entries.reserve(table->NumEntries);
	for (ULONG i = 0; i < table->NumEntries; i++) {
		auto& row = table->Table[i];
		RouteEntry e;
		auto family = row.DestinationPrefix.Prefix.si_family;
		e.Ipv6 = family == AF_INET6;
		e.Destination = AddressText(row.DestinationPrefix.Prefix) + L"/" + std::to_wstring(row.DestinationPrefix.PrefixLength);
		e.NextHop = AddressText(row.NextHop);
		e.Interface = names.Get(row.InterfaceIndex);
		e.Protocol = RouteProtocolName(row.Protocol);
		e.Metric = row.Metric;
		auto key = ((uint64_t)family << 32) | row.InterfaceIndex;
		auto it = metrics.find(key);
		if (it == metrics.end()) {
			MIB_IPINTERFACE_ROW ip{};
			ip.Family = family;
			ip.InterfaceIndex = row.InterfaceIndex;
			it = metrics.emplace(key, ::GetIpInterfaceEntry(&ip) == NO_ERROR ? ip.Metric : 0).first;
		}
		e.InterfaceMetric = it->second;
		entries.push_back(std::move(e));
	}
	::FreeMibTable(table);
	return entries;
}

std::optional<std::vector<DnsCacheRecord>> NetworkTables::ReadDnsCache() {
	// MSFT_DNSClientCache, as PowerShell's Get-DnsClientCache: the documented way (dnsapi's DnsGetCacheDataTable,
	// which older tools used, returns nothing on current Windows, whose ipconfig moved to an undocumented successor)
	wil::com_ptr_nothrow<IWbemLocator> locator;
	auto hr = ::CoCreateInstance(__uuidof(WbemLocator), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator));
	wil::com_ptr_nothrow<IWbemServices> services;
	if (SUCCEEDED(hr)) {
		wil::unique_bstr ns(::SysAllocString(L"ROOT\\StandardCimv2"));
		hr = locator->ConnectServer(ns.get(), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
	}
	if (SUCCEEDED(hr))
		hr = ::CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
			RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
	wil::com_ptr_nothrow<IEnumWbemClassObject> rows;
	if (SUCCEEDED(hr)) {
		wil::unique_bstr language(::SysAllocString(L"WQL"));
		wil::unique_bstr query(::SysAllocString(L"SELECT Entry, Name, Type, Status, Section, TimeToLive, Data FROM MSFT_DNSClientCache"));
		hr = services->ExecQuery(language.get(), query.get(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &rows);
	}
	if (FAILED(hr)) {
		::SetLastError(HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : (DWORD)hr);
		return std::nullopt;
	}

	auto text = [](IWbemClassObject* row, PCWSTR name) {
		wil::unique_variant value;
		return SUCCEEDED(row->Get(name, 0, &value, nullptr, nullptr)) && value.vt == VT_BSTR && value.bstrVal
			? std::wstring(value.bstrVal) : std::wstring();
	};
	auto number = [](IWbemClassObject* row, PCWSTR name) -> uint32_t {
		wil::unique_variant value;
		if (FAILED(row->Get(name, 0, &value, nullptr, nullptr)) || FAILED(::VariantChangeType(&value, &value, 0, VT_UI4)))
			return 0;
		return value.ulVal;
	};
	std::vector<DnsCacheRecord> records;
	for (;;) {
		wil::com_ptr_nothrow<IWbemClassObject> row;
		ULONG count = 0;
		if (rows->Next(WBEM_INFINITE, 1, &row, &count) != WBEM_S_NO_ERROR || count == 0)
			break;
		DnsCacheRecord r;
		r.Name = text(row.get(), L"Name");
		if (r.Name.empty())
			r.Name = text(row.get(), L"Entry");
		r.Type = DnsTypeName((WORD)number(row.get(), L"Type"));
		r.Ttl = number(row.get(), L"TimeToLive");
		r.Section = DnsSectionName(number(row.get(), L"Section"));
		// Status: 0, or a cached negative answer
		switch (number(row.get(), L"Status")) {
			case 0: r.Data = text(row.get(), L"Data"); break;
			case DNS_ERROR_RCODE_NAME_ERROR: r.Data = L"(name does not exist)"; break;
			case DNS_INFO_NO_RECORDS: r.Data = L"(no records)"; break;
			default: r.Data = L"(error " + std::to_wstring(number(row.get(), L"Status")) + L")"; break;
		}
		records.push_back(std::move(r));
	}
	return records;
}

bool NetworkTables::FlushDnsCache() {
	using FlushResolverCache = BOOL(WINAPI*)();
	auto flush = (FlushResolverCache)DnsApi("DnsFlushResolverCache");
	if (!flush)
		return SetError(ERROR_PROC_NOT_FOUND);
	return flush() != FALSE;
}
