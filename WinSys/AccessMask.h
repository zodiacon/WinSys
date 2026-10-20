#pragma once

#include <string>

namespace WinSys {
	struct AccessMaskDecoder final {
		// an access mask in words, for an object type ("Process", "File", "Key"...): the type's specific rights and the
		// standard ones, e.g. "QUERY_LIMITED_INFORMATION | SYNCHRONIZE", or "ALL_ACCESS" for the type's full access. Bits
		// that have no name for the type are shown as a hex remainder
		[[nodiscard]] static std::wstring Decode(std::wstring const& type, uint32_t access);
	};
}
