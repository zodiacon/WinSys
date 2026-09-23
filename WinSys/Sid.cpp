#include "pch.h"
#include "Sid.h"
#include <sddl.h>

using namespace WinSys;

Sid::Sid(PSID sid) {
	::CopySid(sizeof(m_buffer), (PSID)*this, sid);
}

Sid::Sid(const wchar_t* fromString) {
	PSID sid;
	if(::ConvertStringSidToSid(fromString, &sid))
		::CopySid(sizeof(m_buffer), (PSID)*this, sid);
}

Sid WinSys::Sid::CreateWellKnown(WELL_KNOWN_SID_TYPE type, Sid const* domain) noexcept {
	Sid s;
	DWORD size = sizeof(m_buffer);
	::CreateWellKnownSid(type, domain ? *domain : nullptr, s, &size);
	return s;
}

Sid::operator PSID() const noexcept {
	return (PSID)m_buffer;
}

bool Sid::IsValid() const noexcept {
	return ::IsValidSid((PSID)*this);
}

std::wstring Sid::AsString() const {
	PWSTR str;
	std::wstring result;
	if (::ConvertSidToStringSid((PSID)*this, &str)) {
		result = str;
		::LocalFree(str);
	}
	return result;
}

std::wstring Sid::UserName(PSID_NAME_USE use) const {
	WCHAR name[64], domain[64];
	DWORD lname = _countof(name), ldomain = _countof(domain);
	std::wstring username;
	SID_NAME_USE dummy;
	if (use == nullptr)
		use = &dummy;
	if (::LookupAccountSid(nullptr, (PSID)m_buffer, name, &lname, domain, &ldomain, use))
		return std::wstring(domain) + L"\\" + name;
	return L"";
}

