#include "pch.h"
#include "Connections.h"
// the IPv6 tables need ws2ipdef.h, which needs winsock2.h (the lean windows.h leaves winsock.h out, so no clash)
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ip2string.h>
#include <ws2tcpip.h>
#include <algorithm>

#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ws2_32")

namespace {
	// the table, or nullptr (with the last error set); query is GetExtendedTcpTable or GetExtendedUdpTable with its
	// other arguments bound
	template<typename Query>
	std::unique_ptr<BYTE[]> ReadTable(Query const& query) {
		DWORD size = 1 << 16;
		for (int attempt = 0; attempt < 4; attempt++) {
			auto buffer = std::make_unique<BYTE[]>(size);
			auto error = query(buffer.get(), &size);
			if (error == NO_ERROR)
				return buffer;
			if (error != ERROR_INSUFFICIENT_BUFFER) {
				::SetLastError(error);
				return nullptr;
			}
			// connections come and go between the calls
			size += 1 << 12;
		}
		::SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return nullptr;
	}

	uint16_t PortFromTable(DWORD port) {
		// in network order, in the low 16 bits
		return _byteswap_ushort((uint16_t)port);
	}

	std::wstring FormatIPv4(BYTE const* address) {
		WCHAR text[16];
		::RtlIpv4AddressToStringW(reinterpret_cast<in_addr const*>(address), text);
		return text;
	}

	std::wstring FormatIPv6(BYTE const* address, uint32_t scope) {
		WCHAR text[64];
		ULONG len = _countof(text);
		if (::RtlIpv6AddressToStringExW(reinterpret_cast<in6_addr const*>(address), scope, 0, text, &len) != 0)
			return L"";
		return text;
	}
}

namespace WinSys {
	bool Connection::IsTcp() const {
		return Id.Proto == ConnectionProtocol::Tcp || Id.Proto == ConnectionProtocol::Tcp6;
	}

	std::wstring ConnectionInfo::LookupName(std::array<BYTE, 16> const& address, bool v6, uint32_t scope) {
		// once for the process (thread-safe); never cleaned up, as other code may use Winsock too
		static bool const started = [] {
			WSADATA data;
			return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
		}();
		if (!started)
			return L"";
		sockaddr_in6 sa6{};
		sockaddr_in sa4{};
		sockaddr const* sa;
		int len;
		if (v6) {
			sa6.sin6_family = AF_INET6;
			memcpy(&sa6.sin6_addr, address.data(), 16);
			sa6.sin6_scope_id = scope;
			sa = reinterpret_cast<sockaddr const*>(&sa6);
			len = sizeof(sa6);
		}
		else {
			sa4.sin_family = AF_INET;
			memcpy(&sa4.sin_addr, address.data(), 4);
			sa = reinterpret_cast<sockaddr const*>(&sa4);
			len = sizeof(sa4);
		}
		WCHAR host[NI_MAXHOST];
		auto error = ::GetNameInfoW(sa, len, host, _countof(host), nullptr, 0, NI_NAMEREQD);
		if (error) {
			::SetLastError(error);
			return L"";
		}
		return host;
	}

	bool ConnectionInfo::IsUnspecified(std::array<BYTE, 16> const& address, bool v6) {
		return std::all_of(address.begin(), address.begin() + (v6 ? 16 : 4), [](auto b) { return b == 0; });
	}

	PCWSTR ConnectionInfo::ProtocolName(ConnectionProtocol protocol) {
		switch (protocol) {
			case ConnectionProtocol::Tcp: return L"TCP";
			case ConnectionProtocol::Tcp6: return L"TCPv6";
			case ConnectionProtocol::Udp: return L"UDP";
			case ConnectionProtocol::Udp6: return L"UDPv6";
		}
		return L"";
	}

	PCWSTR ConnectionInfo::StateName(Connection const& c) {
		if (!c.IsTcp())
			return L"";
		switch (c.State) {
			case MIB_TCP_STATE_CLOSED: return L"Closed";
			case MIB_TCP_STATE_LISTEN: return L"Listening";
			case MIB_TCP_STATE_SYN_SENT: return L"SYN Sent";
			case MIB_TCP_STATE_SYN_RCVD: return L"SYN Received";
			case MIB_TCP_STATE_ESTAB: return L"Established";
			case MIB_TCP_STATE_FIN_WAIT1: return L"FIN Wait 1";
			case MIB_TCP_STATE_FIN_WAIT2: return L"FIN Wait 2";
			case MIB_TCP_STATE_CLOSE_WAIT: return L"Close Wait";
			case MIB_TCP_STATE_CLOSING: return L"Closing";
			case MIB_TCP_STATE_LAST_ACK: return L"Last ACK";
			case MIB_TCP_STATE_TIME_WAIT: return L"Time Wait";
			case MIB_TCP_STATE_DELETE_TCB: return L"Delete TCB";
		}
		return L"";
	}

	std::optional<std::vector<Connection>> ConnectionInfo::Read(std::optional<uint32_t> pid) {
		std::vector<Connection> result;
		auto wanted = [&](DWORD owner) { return !pid || owner == *pid; };
		auto add = [&](ConnectionKey const& key, DWORD state, LARGE_INTEGER created, std::wstring local, std::wstring remote) {
			Connection c;
			c.Id = key;
			c.State = state;
			c.Created = created.QuadPart;
			c.LocalText = std::move(local);
			c.RemoteText = std::move(remote);
			result.push_back(std::move(c));
		};

		auto tcp4 = ReadTable([](void* buffer, DWORD* size) {
			return ::GetExtendedTcpTable(buffer, size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
			});
		auto tcp6 = ReadTable([](void* buffer, DWORD* size) {
			return ::GetExtendedTcpTable(buffer, size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);
			});
		auto udp4 = ReadTable([](void* buffer, DWORD* size) {
			return ::GetExtendedUdpTable(buffer, size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
			});
		auto udp6 = ReadTable([](void* buffer, DWORD* size) {
			return ::GetExtendedUdpTable(buffer, size, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);
			});
		if (!tcp4 && !tcp6 && !udp4 && !udp6)
			return std::nullopt;

		if (tcp4) {
			auto table = reinterpret_cast<MIB_TCPTABLE_OWNER_MODULE const*>(tcp4.get());
			for (DWORD i = 0; i < table->dwNumEntries; i++) {
				auto& row = table->table[i];
				if (!wanted(row.dwOwningPid))
					continue;
				ConnectionKey key{ ConnectionProtocol::Tcp };
				key.Pid = row.dwOwningPid;
				memcpy(key.LocalAddress.data(), &row.dwLocalAddr, 4);
				memcpy(key.RemoteAddress.data(), &row.dwRemoteAddr, 4);
				key.LocalPort = PortFromTable(row.dwLocalPort);
				// a listening socket has no remote end
				bool listen = row.dwState == MIB_TCP_STATE_LISTEN;
				key.RemotePort = listen ? 0 : PortFromTable(row.dwRemotePort);
				add(key, row.dwState, row.liCreateTimestamp, FormatIPv4(key.LocalAddress.data()),
					listen ? L"" : FormatIPv4(key.RemoteAddress.data()));
			}
		}
		if (tcp6) {
			auto table = reinterpret_cast<MIB_TCP6TABLE_OWNER_MODULE const*>(tcp6.get());
			for (DWORD i = 0; i < table->dwNumEntries; i++) {
				auto& row = table->table[i];
				if (!wanted(row.dwOwningPid))
					continue;
				ConnectionKey key{ ConnectionProtocol::Tcp6 };
				key.Pid = row.dwOwningPid;
				memcpy(key.LocalAddress.data(), row.ucLocalAddr, 16);
				memcpy(key.RemoteAddress.data(), row.ucRemoteAddr, 16);
				key.LocalScope = row.dwLocalScopeId;
				key.RemoteScope = row.dwRemoteScopeId;
				key.LocalPort = PortFromTable(row.dwLocalPort);
				bool listen = row.dwState == MIB_TCP_STATE_LISTEN;
				key.RemotePort = listen ? 0 : PortFromTable(row.dwRemotePort);
				add(key, row.dwState, row.liCreateTimestamp, FormatIPv6(row.ucLocalAddr, row.dwLocalScopeId),
					listen ? L"" : FormatIPv6(row.ucRemoteAddr, row.dwRemoteScopeId));
			}
		}
		if (udp4) {
			auto table = reinterpret_cast<MIB_UDPTABLE_OWNER_MODULE const*>(udp4.get());
			for (DWORD i = 0; i < table->dwNumEntries; i++) {
				auto& row = table->table[i];
				if (!wanted(row.dwOwningPid))
					continue;
				ConnectionKey key{ ConnectionProtocol::Udp };
				key.Pid = row.dwOwningPid;
				memcpy(key.LocalAddress.data(), &row.dwLocalAddr, 4);
				key.LocalPort = PortFromTable(row.dwLocalPort);
				add(key, 0, row.liCreateTimestamp, FormatIPv4(key.LocalAddress.data()), L"");
			}
		}
		if (udp6) {
			auto table = reinterpret_cast<MIB_UDP6TABLE_OWNER_MODULE const*>(udp6.get());
			for (DWORD i = 0; i < table->dwNumEntries; i++) {
				auto& row = table->table[i];
				if (!wanted(row.dwOwningPid))
					continue;
				ConnectionKey key{ ConnectionProtocol::Udp6 };
				key.Pid = row.dwOwningPid;
				memcpy(key.LocalAddress.data(), row.ucLocalAddr, 16);
				key.LocalScope = row.dwLocalScopeId;
				key.LocalPort = PortFromTable(row.dwLocalPort);
				add(key, 0, row.liCreateTimestamp, FormatIPv6(row.ucLocalAddr, row.dwLocalScopeId), L"");
			}
		}
		return result;
	}
}
