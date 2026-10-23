#include "pch.h"
#include "PoolTags.h"
#include <wil/resource.h>
#include <vector>

using namespace WinSys;

namespace {
	std::wstring Widen(std::string_view text) {
		std::wstring result(text.size(), L'\0');
		int count = ::MultiByteToWideChar(CP_ACP, 0, text.data(), (int)text.size(), result.data(), (int)result.size());
		result.resize(count > 0 ? count : 0);
		return result;
	}

	std::string_view Trim(std::string_view text) {
		auto start = text.find_first_not_of(" \t\r");
		if (start == std::string_view::npos)
			return {};
		auto end = text.find_last_not_of(" \t\r");
		return text.substr(start, end - start + 1);
	}
}

std::wstring PoolTagDescriptions::TagText(uint32_t tag) {
	std::wstring text;
	for (int i = 0; i < 4; i++) {
		auto c = (wchar_t)((tag >> (i * 8)) & 0xff);
		text += c >= 0x20 && c < 0x7f ? c : L'.';
	}
	return text;
}

void PoolTagDescriptions::Parse(std::string_view text) {
	size_t pos = 0;
	while (pos < text.size()) {
		auto end = text.find('\n', pos);
		auto line = text.substr(pos, end == std::string_view::npos ? std::string_view::npos : end - pos);
		pos = end == std::string_view::npos ? text.size() : end + 1;
		if (line.size() < 6 || line.starts_with("//") || line.starts_with("rem") || line[4] != ' ')
			continue;
		// the tag is the first four characters, spaces included (the kernel pads short tags with spaces)
		uint32_t tag = 0;
		for (int i = 0; i < 4; i++)
			tag |= (uint32_t)(uint8_t)line[i] << (i * 8);
		// " - binary - description"
		auto rest = line.substr(5);
		auto dash = rest.find('-');
		if (dash == std::string_view::npos)
			continue;
		rest = rest.substr(dash + 1);
		PoolTagDescription desc;
		auto dash2 = rest.find(" - ");
		if (dash2 == std::string_view::npos)
			desc.Binary = Widen(Trim(rest));
		else {
			desc.Binary = Widen(Trim(rest.substr(0, dash2)));
			desc.Description = Widen(Trim(rest.substr(dash2 + 3)));
		}
		m_Tags.try_emplace(tag, std::move(desc));
	}
}

std::wstring PoolTagDescriptions::FindFile() {
	WCHAR folder[MAX_PATH];
	auto length = ::GetEnvironmentVariable(L"ProgramFiles(x86)", folder, _countof(folder));
	if (length == 0 || length >= _countof(folder))
		return {};
	std::wstring base = folder;
	for (auto arch : { L"x64", L"x86" }) {
		auto path = base + L"\\Windows Kits\\10\\Debuggers\\" + arch + L"\\triage\\pooltag.txt";
		if (::GetFileAttributes(path.c_str()) != INVALID_FILE_ATTRIBUTES)
			return path;
	}
	return {};
}

bool PoolTagDescriptions::Load(std::wstring const& path) {
	wil::unique_hfile file(::CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
	LARGE_INTEGER size;
	if (!file || !::GetFileSizeEx(file.get(), &size) || size.QuadPart > (16 << 20))
		return false;
	std::vector<char> text((size_t)size.QuadPart);
	DWORD read;
	if (!::ReadFile(file.get(), text.data(), (DWORD)text.size(), &read, nullptr))
		return false;
	Parse(std::string_view(text.data(), read));
	return true;
}

PoolTagDescription const* PoolTagDescriptions::Find(uint32_t tag) const {
	auto it = m_Tags.find(tag);
	return it == m_Tags.end() ? nullptr : &it->second;
}
