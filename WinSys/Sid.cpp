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
		// well-known SIDs such as Everyone have no domain
		return *domain ? std::wstring(domain) + L"\\" + name : std::wstring(name);
	return L"";
}

std::wstring Sid::AppContainerMoniker() const {
	using LookupMoniker = HRESULT(WINAPI*)(PSID, PWSTR*);
	using FreeMemory = BOOLEAN(WINAPI*)(PVOID);
	static auto hKernelBase = ::GetModuleHandle(L"kernelbase");
	static auto lookup = reinterpret_cast<LookupMoniker>(::GetProcAddress(hKernelBase, "AppContainerLookupMoniker"));
	static auto free = reinterpret_cast<FreeMemory>(::GetProcAddress(hKernelBase, "AppContainerFreeMemory"));
	PWSTR moniker = nullptr;
	if (!IsValid() || !lookup || !free || FAILED(lookup((PSID)m_buffer, &moniker)) || !moniker)
		return L"";
	std::wstring text(moniker);
	free(moniker);
	return text;
}
