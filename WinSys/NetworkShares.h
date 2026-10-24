#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// The local computer's shares (NetShareEnum). Its fullest level (502: the path, use counts and share permissions)
// and level 2 (without the permissions) are documented to need administrator rights (current Windows gives a local
// caller both without them); anyone gets level 1 (name, type and comment), so Enum falls back level by level on access
// denied and says which it got. Each share's flags (offline caching, access-based enumeration,
// encryption) are NetShareGetInfo's level 1005, which anyone may read.
//
namespace WinSys {
	// share permissions are their own: Full Control, Change and Read are these masks
	struct ShareAccessEntry {
		std::wstring Trustee;	// the account's name, else the SID
		uint32_t Mask{ 0 };
		bool Allow{ true };
	};

	struct NetworkShare {
		std::wstring Name, Path, Remark;
		uint32_t Type{ 0 };	// STYPE_*: the kind in the low bits, STYPE_SPECIAL and STYPE_TEMPORARY above
		std::optional<uint32_t> CurrentUses, MaxUses;	// MaxUses UINT32_MAX: unlimited; nothing below level 2
		std::optional<uint32_t> Flags;	// SHI1005_FLAGS_*
		bool HasPermissions{ false };	// level 502 and a DACL; none (with HasPermissions): everyone has full control
		std::vector<ShareAccessEntry> Permissions;
	};

	struct NetworkShares final {
		// level: the NetShareEnum level the shares came at (502, 2 or 1). Nothing (with the last error set) on failure
		[[nodiscard]] static std::optional<std::vector<NetworkShare>> Enum(uint32_t& level);
		// "Disk", "Print queue", "Device", "IPC"... with ", special" and ", temporary"
		[[nodiscard]] static std::wstring TypeName(uint32_t type);
		// "Full Control", "Change", "Read", else the mask in hex
		[[nodiscard]] static std::wstring RightsName(uint32_t mask);
		// how the share is cached offline: "Manual", "Automatic (documents)", "Automatic (programs)", "None"
		[[nodiscard]] static std::wstring CachingName(uint32_t flags);
	};
}
