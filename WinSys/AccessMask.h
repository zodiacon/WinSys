#pragma once

#include <string>
#include <vector>

namespace WinSys {
	struct AccessRight {
		uint32_t Mask;
		PCWSTR Name;	// "QUERY_STATE"
	};

	struct AccessMaskDecoder final {
		// an access mask in words, for an object type ("Process", "File", "Key"...): the type's specific rights and the
		// standard ones, e.g. "QUERY_LIMITED_INFORMATION | SYNCHRONIZE", or "ALL_ACCESS" for the type's full access. Bits
		// that have no name for the type are shown as a hex remainder
		[[nodiscard]] static std::wstring Decode(std::wstring const& type, uint32_t access);
		// the type's specific rights, one bit each (not combinations such as KEY_READ); empty for a type without names
		[[nodiscard]] static std::vector<AccessRight> GetSpecificRights(std::wstring const& type);
		// DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE
		[[nodiscard]] static std::vector<AccessRight> GetStandardRights();
	};
}
