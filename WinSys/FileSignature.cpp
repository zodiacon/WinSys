#include "pch.h"
#include "FileSignature.h"
#include <wil/resource.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")

using namespace WinSys;

namespace {
	// WinVerifyTrust over a file or a catalog member; the signer from the provider's state
	LONG VerifyTrust(WINTRUST_DATA& data, std::wstring& signer) {
		GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		data.cbStruct = sizeof(data);
		data.dwUIChoice = WTD_UI_NONE;
		data.fdwRevocationChecks = WTD_REVOKE_NONE;
		data.dwStateAction = WTD_STATEACTION_VERIFY;
		data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
		auto status = ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);

		if (auto provider = ::WTHelperProvDataFromStateData(data.hWVTStateData)) {
			if (auto sgnr = ::WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0); sgnr && sgnr->csCertChain > 0) {
				WCHAR name[256];
				if (::CertGetNameString(sgnr->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, _countof(name)) > 1)
					signer = name;
			}
		}
		data.dwStateAction = WTD_STATEACTION_CLOSE;
		::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
		return status;
	}

	// the catalog that lists the file's hash, if any
	std::optional<LONG> VerifyCatalog(PCWSTR path, HANDLE hFile, std::wstring& signer) {
		HCATADMIN hAdmin;
		if (!::CryptCATAdminAcquireContext2(&hAdmin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
			return std::nullopt;

		std::optional<LONG> result;
		DWORD size = 0;
		::CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &size, nullptr, 0);
		std::vector<BYTE> hash(size);
		if (size && ::CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &size, hash.data(), 0)) {
			if (auto hCat = ::CryptCATAdminEnumCatalogFromHash(hAdmin, hash.data(), size, 0, nullptr)) {
				CATALOG_INFO info{ sizeof(info) };
				if (::CryptCATCatalogInfoFromContext(hCat, &info, 0)) {
					// the member tag is the hash in hex
					std::wstring tag;
					for (auto b : hash) {
						WCHAR hex[4];
						::StringCchPrintf(hex, _countof(hex), L"%02X", b);
						tag += hex;
					}
					WINTRUST_CATALOG_INFO catalog{ sizeof(catalog) };
					catalog.pcwszCatalogFilePath = info.wszCatalogFile;
					catalog.pcwszMemberFilePath = path;
					catalog.pcwszMemberTag = tag.c_str();
					catalog.hMemberFile = hFile;
					catalog.pbCalculatedFileHash = hash.data();
					catalog.cbCalculatedFileHash = size;
					catalog.hCatAdmin = hAdmin;
					WINTRUST_DATA data{};
					data.dwUnionChoice = WTD_CHOICE_CATALOG;
					data.pCatalog = &catalog;
					result = VerifyTrust(data, signer);
				}
				::CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
			}
		}
		::CryptCATAdminReleaseContext(hAdmin, 0);
		return result;
	}

	bool IsUnsigned(LONG status) {
		return status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_PROVIDER_UNKNOWN;
	}
}

SignatureInfo FileSignature::Verify(PCWSTR path) {
	SignatureInfo info;
	wil::unique_hfile file(::CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		OPEN_EXISTING, 0, nullptr));
	if (!file) {
		info.Error = ::GetLastError();
		return info;
	}

	WINTRUST_FILE_INFO fileInfo{ sizeof(fileInfo) };
	fileInfo.pcwszFilePath = path;
	fileInfo.hFile = file.get();
	WINTRUST_DATA data{};
	data.dwUnionChoice = WTD_CHOICE_FILE;
	data.pFile = &fileInfo;
	auto status = VerifyTrust(data, info.Signer);
	if (IsUnsigned(status)) {
		::SetFilePointer(file.get(), 0, nullptr, FILE_BEGIN);
		if (auto catalog = VerifyCatalog(path, file.get(), info.Signer)) {
			info.Catalog = true;
			status = *catalog;
		}
	}

	if (status == ERROR_SUCCESS)
		info.Status = SignatureStatus::Valid;
	else if (IsUnsigned(status))
		info.Status = SignatureStatus::NotSigned;
	else
		info.Status = SignatureStatus::Invalid;
	info.Error = static_cast<DWORD>(status);
	return info;
}
