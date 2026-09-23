#pragma once

#include <string>

namespace WinSys {
	class Sid final {
	public:
		Sid() = default;
		explicit Sid(PSID sid);
		explicit Sid(const wchar_t* fromString);
		static Sid CreateWellKnown(WELL_KNOWN_SID_TYPE type, Sid const* domain = nullptr) noexcept;

		operator PSID() const noexcept;

		bool IsValid() const noexcept;
		operator bool() const noexcept {
			return IsValid();
		}

		std::wstring AsString() const;
		std::wstring UserName(PSID_NAME_USE use = nullptr) const;
	private:
		BYTE m_buffer[SECURITY_MAX_SID_SIZE]{};
	};
}
