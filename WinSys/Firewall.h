#pragma once

#include <vector>
#include <optional>
#include <string>

namespace WinSys {
	struct FirewallRule {
		std::wstring Name;			// localized (an indirect "@file,-id" name resolved)
		std::wstring Description;
		std::wstring Grouping;		// the rule group, localized; empty if none
		std::wstring Application;	// the program's path; empty for any
		std::wstring Service;		// the service's short name; empty for any ("*": services only)
		std::wstring LocalPorts, RemotePorts, LocalAddresses, RemoteAddresses;	// "*" for any
		std::wstring IcmpTypes;		// "type:code,..." for ICMP rules
		std::wstring InterfaceTypes;	// "All", "LAN", "Wireless", "RemoteAccess"
		std::wstring PackageId;		// an AppContainer's SID, for a packaged app's rule
		int32_t Protocol{ 256 };	// IANA protocol number; 256 is any
		uint32_t Profiles{ 0 };		// NET_FW_PROFILE2_* bits
		bool Inbound{ true };
		bool Allow{ true };
		bool Enabled{ false };
		bool EdgeTraversal{ false };
		// as stored, for finding the rule again (SetEnabled): the names may be indirect strings
		std::wstring RawName, RawGrouping;
	};

	struct FirewallProfile {
		uint32_t Type{ 0 };			// NET_FW_PROFILE2_DOMAIN, PRIVATE or PUBLIC
		bool Enabled{ false };
		bool BlockAllInbound{ false };	// even the allowed inbound connections
		bool InboundAllowed{ false }, OutboundAllowed{ false };	// the default actions
	};

	struct FirewallPolicy {
		uint32_t CurrentProfiles{ 0 };	// the active networks' profiles, NET_FW_PROFILE2_* bits
		std::vector<FirewallProfile> Profiles;	// domain, private, public
	};

	//
	// Windows Defender Firewall's rules and profiles, through its COM API (HNetCfg.FwPolicy2, INetFwPolicy2; COM must be
	// initialized on the calling thread). Reading needs no elevation; changing a rule does (E_ACCESSDENIED otherwise).
	// Failures return nothing, with the HRESULT as the last error.
	//
	struct Firewall final {
		[[nodiscard]] static std::optional<std::vector<FirewallRule>> EnumRules();
		[[nodiscard]] static std::optional<FirewallPolicy> GetPolicy();
		// turns a rule on or off. Rule names aren't unique, so the rule is found again by everything that identifies it
		// (SameRule); false with ERROR_NOT_FOUND if it's gone, or with the HRESULT
		static bool SetEnabled(FirewallRule const& rule, bool enabled);

		// the same rule: its raw name and group, direction, action, protocol, ports, addresses, program, service,
		// package and profiles (not its enabled state)
		[[nodiscard]] static bool SameRule(FirewallRule const& a, FirewallRule const& b);
		// "TCP", "UDP", "ICMPv4", "ICMPv6", "Any", else the number
		[[nodiscard]] static std::wstring ProtocolName(int32_t protocol);
		// "Domain, Private", "All" (every profile)
		[[nodiscard]] static std::wstring ProfilesText(uint32_t profiles);
	};
}
