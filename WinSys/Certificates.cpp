#include "pch.h"
#include "Certificates.h"
#include <wincrypt.h>
#include <wil/resource.h>

#pragma comment(lib, "crypt32")

using namespace WinSys;

namespace {
	const DWORD Encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	const int64_t TicksPerDay = 864000000000LL;

	DWORD LocationFlags(CertificateLocation location) {
		return location == CertificateLocation::LocalMachine ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER;
	}

	std::wstring Hex(BYTE const* data, DWORD size, bool reverse = false) {
		static const WCHAR digits[] = L"0123456789ABCDEF";
		std::wstring text;
		text.reserve(size * 2);
		for (DWORD i = 0; i < size; i++) {
			auto b = data[reverse ? size - 1 - i : i];
			text += digits[b >> 4];
			text += digits[b & 15];
		}
		return text;
	}

	int64_t ToInt(FILETIME const& ft) {
		return (int64_t)ULARGE_INTEGER{ ft.dwLowDateTime, ft.dwHighDateTime }.QuadPart;
	}

	std::wstring OidName(PCSTR oid, DWORD group) {
		if (!oid)
			return L"";
		if (auto info = ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void*)oid, group); info && info->pwszName)
			return info->pwszName;
		return std::wstring(oid, oid + strlen(oid));
	}

	std::wstring NameOf(PCCERT_CONTEXT cert, DWORD type, DWORD flags) {
		WCHAR name[512];
		return ::CertGetNameString(cert, type, flags, nullptr, name, _countof(name)) > 1 ? name : L"";
	}

	std::vector<std::wstring> PhysicalStores(CertificateLocation location, std::wstring const& store) {
		std::vector<std::wstring> names;
		::CertEnumPhysicalStore(store.c_str(), LocationFlags(location), &names,
			[](void const*, DWORD, LPCWSTR name, PCERT_PHYSICAL_STORE_INFO, void*, void* arg) -> BOOL {
				static_cast<std::vector<std::wstring>*>(arg)->push_back(name);
				return TRUE;
			});
		return names;
	}

	// when the certificate went into the physical store: its registry key's last write (a user's own may be a file)
	int64_t AddedTime(CertificateLocation location, std::wstring const& store, std::wstring const& physical, std::wstring const& thumbprint) {
		bool machine = location == CertificateLocation::LocalMachine;
		PCWSTR base = nullptr;
		if (::_wcsicmp(physical.c_str(), L".Default") == 0)
			base = machine ? L"SOFTWARE\\Microsoft\\SystemCertificates\\" : L"Software\\Microsoft\\SystemCertificates\\";
		else if (::_wcsicmp(physical.c_str(), L".GroupPolicy") == 0)
			base = machine ? L"SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\" : L"Software\\Policies\\Microsoft\\SystemCertificates\\";
		else if (::_wcsicmp(physical.c_str(), L".Enterprise") == 0 && machine)
			base = L"SOFTWARE\\Microsoft\\EnterpriseCertificates\\";
		if (!base)
			return 0;
		auto path = std::wstring(base) + store + L"\\Certificates\\" + thumbprint;
		wil::unique_hkey key;
		if (::RegOpenKeyEx(machine ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, path.c_str(), 0, KEY_QUERY_VALUE, key.put()) == ERROR_SUCCESS) {
			FILETIME written{};
			if (::RegQueryInfoKey(key.get(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &written) == ERROR_SUCCESS)
				return ToInt(written);
		}
		if (!machine && ::_wcsicmp(physical.c_str(), L".Default") == 0) {
			// %APPDATA%\Microsoft\SystemCertificates\<store>\Certificates\<thumbprint> (the user's My certificates, mostly)
			WCHAR appData[MAX_PATH];
			if (::ExpandEnvironmentStrings(L"%APPDATA%", appData, _countof(appData)) && appData[0] != L'%') {
				auto file = std::wstring(appData) +L"\\Microsoft\\SystemCertificates\\" + store + L"\\Certificates\\" + thumbprint;
				WIN32_FILE_ATTRIBUTE_DATA data;
				if (::GetFileAttributesEx(file.c_str(), GetFileExInfoStandard, &data))
					return ToInt(data.ftLastWriteTime);
			}
		}
		return 0;
	}

	CertificateInfo ReadCertificate(PCCERT_CONTEXT cert) {
		CertificateInfo c;
		c.Subject = NameOf(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
		c.Issuer = NameOf(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);
		c.FriendlyName = NameOf(cert, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0);
		// the friendly name falls back to the subject: only a real one
		if (c.FriendlyName == c.Subject) {
			DWORD size = 0;
			if (!::CertGetCertificateContextProperty(cert, CERT_FRIENDLY_NAME_PROP_ID, nullptr, &size))
				c.FriendlyName.clear();
		}
		auto info = cert->pCertInfo;
		c.SerialNumber = Hex(info->SerialNumber.pbData, info->SerialNumber.cbData, true);	// stored little-endian
		BYTE hash[20];
		DWORD size = sizeof(hash);
		if (::CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash, &size))
			c.Thumbprint = Hex(hash, size);
		c.KeyAlgorithm = OidName(info->SubjectPublicKeyInfo.Algorithm.pszObjId, CRYPT_PUBKEY_ALG_OID_GROUP_ID);
		c.KeyBits = ::CertGetPublicKeyLength(Encoding, &info->SubjectPublicKeyInfo);
		c.SignatureAlgorithm = OidName(info->SignatureAlgorithm.pszObjId, CRYPT_SIGN_ALG_OID_GROUP_ID);
		c.NotBefore = ToInt(info->NotBefore);
		c.NotAfter = ToInt(info->NotAfter);
		c.SelfSigned = ::CertCompareCertificateName(Encoding, &info->Subject, &info->Issuer) != FALSE;
		size = 0;
		c.HasPrivateKey = ::CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size) != FALSE;
		// the usages the extension and the properties allow together; none listed (CRYPT_E_NOT_FOUND): any purpose
		size = 0;
		if (::CertGetEnhancedKeyUsage(cert, 0, nullptr, &size) && size) {
			std::vector<BYTE> buffer(size);
			auto usage = (PCERT_ENHKEY_USAGE)buffer.data();
			if (::CertGetEnhancedKeyUsage(cert, 0, usage, &size))
				for (DWORD i = 0; i < usage->cUsageIdentifier; i++)
					c.Purposes.push_back(OidName(usage->rgpszUsageIdentifier[i], CRYPT_ENHKEY_USAGE_OID_GROUP_ID));
		}
		c.Encoded.assign(cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);
		return c;
	}

	std::optional<CertificateTrustList> ReadCachedList(PCWSTR value, PCWSTR syncValue) {
		const PCWSTR key = L"SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\AutoUpdate";
		DWORD size = 0;
		if (::RegGetValue(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_BINARY, nullptr, nullptr, &size) != ERROR_SUCCESS || size == 0)
			return {};
		std::vector<BYTE> data(size);
		if (::RegGetValue(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_BINARY, nullptr, data.data(), &size) != ERROR_SUCCESS)
			return {};
		auto list = Certificates::ParseTrustList(data.data(), size);
		if (list) {
			int64_t sync = 0;
			DWORD syncSize = sizeof(sync);
			if (::RegGetValue(HKEY_LOCAL_MACHINE, key, syncValue, RRF_RT_REG_BINARY, nullptr, &sync, &syncSize) == ERROR_SUCCESS && syncSize == sizeof(sync))
				list->LastSync = sync;
		}
		return list;
	}
}

std::vector<CertificateStoreInfo> Certificates::EnumStores(CertificateLocation location) {
	struct Context {
		CertificateLocation Location;
		std::vector<CertificateStoreInfo> Stores;
	} context{ location };
	::CertEnumSystemStore(LocationFlags(location), nullptr, &context,
		[](void const* store, DWORD, PCERT_SYSTEM_STORE_INFO, void*, void* arg) -> BOOL {
			auto ctx = static_cast<Context*>(arg);
			CertificateStoreInfo info;
			info.Location = ctx->Location;
			info.Name = (PCWSTR)store;
			auto display = ::CryptFindLocalizedName(info.Name.c_str());
			info.DisplayName = display ? display : info.Name;
			ctx->Stores.push_back(std::move(info));
			return TRUE;
		});
	for (auto& s : context.Stores)
		s.PhysicalStores = PhysicalStores(location, s.Name);
	return std::move(context.Stores);
}

std::optional<std::vector<CertificateInfo>> Certificates::Read(CertificateLocation location, std::wstring const& store) {
	auto physical = PhysicalStores(location, store);
	std::vector<CertificateInfo> result;
	bool opened = false;
	DWORD error = 0;
	for (auto& p : physical) {
		// a user's view of the machine's certificates: they're the machine's
		if (location == CertificateLocation::CurrentUser && ::_wcsicmp(p.c_str(), L".LocalMachine") == 0)
			continue;
		auto name = store + L"\\" + p;
		HCERTSTORE hStore = ::CertOpenStore(CERT_STORE_PROV_PHYSICAL_W, 0, 0,
			LocationFlags(location) | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, name.c_str());
		if (!hStore) {
			error = ::GetLastError();
			continue;
		}
		opened = true;
		PCCERT_CONTEXT cert = nullptr;
		while ((cert = ::CertEnumCertificatesInStore(hStore, cert)) != nullptr) {
			auto c = ReadCertificate(cert);
			c.Location = location;
			c.Store = store;
			c.PhysicalStore = p;
			c.Added = AddedTime(location, store, p, c.Thumbprint);
			result.push_back(std::move(c));
		}
		::CertCloseStore(hStore, 0);
	}
	if (!opened && error) {
		::SetLastError(error);
		return {};
	}
	return result;
}

std::optional<CertificateTrustList> Certificates::ParseTrustList(void const* data, size_t size) {
	if (!data || size == 0)
		return {};
	auto ctl = ::CertCreateCTLContext(Encoding, (BYTE const*)data, (DWORD)size);
	if (!ctl)
		return {};
	CertificateTrustList list;
	auto info = ctl->pCtlInfo;
	list.ThisUpdate = ToInt(info->ThisUpdate);
	for (DWORD i = 0; i < info->cCTLEntry; i++) {
		auto& id = info->rgCTLEntry[i].SubjectIdentifier;
		list.Thumbprints.insert(Hex(id.pbData, id.cbData));
	}
	::CertFreeCTLContext(ctl);
	return list;
}

std::optional<CertificateTrustList> Certificates::ReadRootProgram() {
	return ReadCachedList(L"EncodedCtl", L"LastSyncTime");
}

std::optional<CertificateTrustList> Certificates::ReadDisallowed() {
	return ReadCachedList(L"DisallowedCertEncodedCtl", L"DisallowedCertLastSyncTime");
}

bool Certificates::IsWindowsRoot(CertificateInfo const& cert) {
	// the Insider builds' roots, in their own physical store
	if (::_wcsicmp(cert.PhysicalStore.c_str(), L".Flight") == 0)
		return true;
	// Windows' own legacy roots, which the program's list doesn't have
	static const PCWSTR legacy[] = {
		L"7F88CD7223F3C813818C994614A89C99FA3B5247",	// Microsoft Authenticode(tm) Root Authority
		L"245C97DF7514E7CF2DF8BE72AE957B9E04741E85",	// Copyright (c) 1997 Microsoft Corp.
	};
	for (auto t : legacy)
		if (cert.Thumbprint == t)
			return true;
	return false;
}

bool Certificates::IsRootStore(std::wstring const& store) {
	return ::_wcsicmp(store.c_str(), L"Root") == 0 || ::_wcsicmp(store.c_str(), L"AuthRoot") == 0;
}

bool Certificates::IsTrustStore(std::wstring const& store) {
	for (auto name : { L"Root", L"AuthRoot", L"CA", L"TrustedPublisher", L"TrustedPeople" })
		if (::_wcsicmp(store.c_str(), name) == 0)
			return true;
	return false;
}

CertificateAssessment Certificates::Assess(CertificateInfo const& cert, CertificateTrustList const* program,
	CertificateTrustList const* disallowed, int64_t now) {
	CertificateAssessment a;
	auto add = [&](CertificateConcern concern, std::wstring const& text) {
		if (concern > a.Concern)
			a.Concern = concern;
		a.Text += (a.Text.empty() ? L"" : L"; ") + text;
	};
	bool trusted = IsTrustStore(cert.Store), root = IsRootStore(cert.Store);
	if (trusted && disallowed && disallowed->Thumbprints.contains(cert.Thumbprint))
		add(CertificateConcern::Danger, L"Trusted, but on Microsoft's disallowed list");
	if (root && cert.HasPrivateKey)
		add(CertificateConcern::Danger, L"A trusted root whose private key is on this machine");
	bool vouched = root && (IsWindowsRoot(cert) || (program && program->Thumbprints.contains(cert.Thumbprint)));
	if (root && program && !vouched)
		add(CertificateConcern::NotInProgram, L"Not in Microsoft's root program");
	// an addition only where it grants trust deliberately (Windows caches intermediates in CA, and downloads the program's
	// roots into AuthRoot, by itself), and not of a root Microsoft vouches for: an update rewrites their keys, so the
	// registry's write time isn't when they came
	bool deliberate = ::_wcsicmp(cert.Store.c_str(), L"Root") == 0 || ::_wcsicmp(cert.Store.c_str(), L"TrustedPublisher") == 0
		|| ::_wcsicmp(cert.Store.c_str(), L"TrustedPeople") == 0;
	if (deliberate && !vouched && cert.Added && now >= cert.Added && now - cert.Added < RecentDays * TicksPerDay) {
		auto days = (now - cert.Added) / TicksPerDay;
		add(CertificateConcern::Recent, days == 0 ? std::wstring(L"Added today") : days == 1 ? std::wstring(L"Added yesterday")
			: L"Added " + std::to_wstring(days) + L" days ago");
	}
	if (cert.NotAfter && cert.NotAfter < now)
		add(CertificateConcern::Expired, L"Expired");
	return a;
}

PCWSTR Certificates::LocationName(CertificateLocation location) {
	return location == CertificateLocation::LocalMachine ? L"Local Machine" : L"Current User";
}
