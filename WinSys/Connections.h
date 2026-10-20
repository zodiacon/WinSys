#pragma once

#include <array>
#include <optional>
#include <vector>
#include <string>

namespace WinSys {
	enum class ConnectionProtocol : uint8_t { Tcp, Tcp6, Udp, Udp6 };

	// what tells connections apart from one read to the next
	struct ConnectionKey {
		ConnectionProtocol Proto;
		std::array<BYTE, 16> LocalAddress, RemoteAddress;	// IPv4 in the first 4 bytes
		uint32_t LocalScope, RemoteScope;
		uint16_t LocalPort, RemotePort;	// host order
		uint32_t Pid;

		auto operator<=>(ConnectionKey const&) const = default;
	};

	struct Connection {
		ConnectionKey Id;
		DWORD State;		// MIB_TCP_STATE; 0 for UDP
		int64_t Created;	// FILETIME, 0 if unknown
		std::wstring LocalText, RemoteText;	// the addresses, formatted once; no remote end: empty

		[[nodiscard]] bool IsTcp() const;
	};

	//
	// The system's TCP connections (listening ones too) and UDP endpoints, IPv4 and IPv6, from the IP helper's owner
	// tables (GetExtendedTcpTable/GetExtendedUdpTable: the owning process and the creation time; no elevation needed).
	// The header uses no IP Helper types (see Network.h).
	//
	struct ConnectionInfo final {
		// the connections (pid: only that process's); nothing (with the last error set) if none of the tables can be read
		[[nodiscard]] static std::optional<std::vector<Connection>> Read(std::optional<uint32_t> pid = std::nullopt);
		[[nodiscard]] static PCWSTR ProtocolName(ConnectionProtocol protocol);
		// "Established", "Listening"...; empty for UDP
		[[nodiscard]] static PCWSTR StateName(Connection const& c);
	};
}
