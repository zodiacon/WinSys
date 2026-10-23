#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

//
// Pool tag descriptions, from pooltag.txt (the Debugging Tools for Windows' triage folder has it): lines of
// "<tag> - <binary> - <description>", comments starting with "//" or "rem". The counters themselves come from
// SystemInfo::GetPoolTagInformation.
//

namespace WinSys {
	struct PoolTagDescription {
		std::wstring Binary;		// the driver or binary using the tag; "<unknown>" in the file for some
		std::wstring Description;
	};

	class PoolTagDescriptions final {
	public:
		// the file's text (ANSI); later lines for the same tag are ignored
		void Parse(std::string_view text);
		// the Debugging Tools' pooltag.txt (x64, then x86, under the Windows Kits); empty if not installed
		[[nodiscard]] static std::wstring FindFile();
		// reads and parses a file; false if it can't be read
		bool Load(std::wstring const& path);

		// a tag's description, by the tag as the kernel has it (four bytes, the first in the low byte)
		[[nodiscard]] PoolTagDescription const* Find(uint32_t tag) const;
		[[nodiscard]] size_t GetCount() const {
			return m_Tags.size();
		}

		// the tag as text: its four characters, unprintable ones as '.'
		[[nodiscard]] static std::wstring TagText(uint32_t tag);

	private:
		std::unordered_map<uint32_t, PoolTagDescription> m_Tags;
	};
}
