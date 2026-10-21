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
		// the DNS name of an address (a reverse lookup, GetNameInfoW with NI_NAMEREQD), empty if it has none (or with
		// the last error set on failure). It blocks, seconds for an address without a name, so call it off the UI
		// thread; it's thread-safe. v6: all 16 bytes with the scope, else the first 4
		[[nodiscard]] static std::wstring LookupName(std::array<BYTE, 16> const& address, bool v6, uint32_t scope = 0);
		// 0.0.0.0 or ::, a listening socket's (no name to look up)
		[[nodiscard]] static bool IsUnspecified(std::array<BYTE, 16> const& address, bool v6);
		// a TCP connection over IPv4 that has a remote end (not listening, closed or in TIME_WAIT): one Close can reset
		// (the IP helper has no way for IPv6)
		[[nodiscard]] static bool CanClose(Connection const& c);
		// resets the connection (SetTcpEntry with MIB_TCP_STATE_DELETE_TCB), as TCPView's Close Connection; needs
		// elevation. False with the last error set (ERROR_NOT_SUPPORTED if not CanClose)
		static bool Close(Connection const& c);
	};
}
