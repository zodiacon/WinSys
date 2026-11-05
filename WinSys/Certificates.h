#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

//
// The certificate stores of the machine and the current user (crypt32: CertEnumSystemStore, CertEnumPhysicalStore) and
// their certificates, each read from its physical store (".Default": the location's own registry key, ".GroupPolicy",
// ".Enterprise"; a user's ".LocalMachine", the machine's certificates the user's view inherits, is left out: they're the
// machine's), with when it was added (its registry key's last write, or a user's file under AppData). Judged against
// Microsoft's lists as Windows caches them (the AuthRoot AutoUpdate key's EncodedCtl: the roots of the Microsoft Trusted
// Root Program; DisallowedCertEncodedCtl: the certificates Microsoft distrusts), with no download. No elevation needed.
//
namespace WinSys {
	enum class CertificateLocation : uint8_t { LocalMachine, CurrentUser };

	struct CertificateStoreInfo {
		CertificateLocation Location{ CertificateLocation::LocalMachine };
		std::wstring Name;			// "Root"
		std::wstring DisplayName;	// "Trusted Root Certification Authorities" (CryptFindLocalizedName), else the name
		std::vector<std::wstring> PhysicalStores;	// ".Default", ".GroupPolicy"...
	};

	struct CertificateInfo {
		CertificateLocation Location{ CertificateLocation::LocalMachine };
		std::wstring Store;			// the system store: "Root"
		std::wstring PhysicalStore;	// ".Default"
		std::wstring Subject, Issuer;	// simple display names
		std::wstring FriendlyName;
		std::wstring SerialNumber;	// hex, most significant byte first, as certmgr shows it
		std::wstring Thumbprint;	// SHA-1, upper-case hex
		std::wstring KeyAlgorithm;	// "RSA", "ECC"
		uint32_t KeyBits{ 0 };
		std::wstring SignatureAlgorithm;	// "sha256RSA"
		std::vector<std::wstring> Purposes;	// the enhanced key usages' names; empty: any purpose
		int64_t NotBefore{ 0 }, NotAfter{ 0 };	// FILETIME, UTC
		int64_t Added{ 0 };			// FILETIME, UTC: when its registry key (or file) was last written; 0 if unknown
		bool SelfSigned{ false };	// its subject is its issuer
		bool HasPrivateKey{ false };	// a private key on this machine (CERT_KEY_PROV_INFO_PROP_ID)
		std::vector<uint8_t> Encoded;	// DER, for viewing it
	};

	// a Microsoft certificate trust list as cached: the certificates' SHA-1 thumbprints (upper-case hex)
	struct CertificateTrustList {
		std::unordered_set<std::wstring> Thumbprints;
		int64_t ThisUpdate{ 0 };	// FILETIME: the list's date
		int64_t LastSync{ 0 };		// FILETIME: when Windows last downloaded it; 0 if unknown
	};

	enum class CertificateConcern : uint8_t {
		None,
		Expired,		// no longer valid: harmless, but clutter
		Recent,			// added to a trust store in the last RecentDays
		NotInProgram,	// a trusted root Microsoft's program doesn't have: a company's, a tool's (Fiddler) or an attacker's
		Danger,			// trusted but on Microsoft's disallowed list, or a trusted root whose private key is here (anyone with it
						// can make certificates this machine trusts)
	};

	struct CertificateAssessment {
		CertificateConcern Concern{ CertificateConcern::None };	// the worst
		std::wstring Text;	// every reason, "; " between: "Not in Microsoft's root program; added 3 days ago"
	};

	struct Certificates final {
		static constexpr int RecentDays = 30;

		[[nodiscard]] static std::vector<CertificateStoreInfo> EnumStores(CertificateLocation location);
		// the store's certificates from each of its physical stores; nothing (the last error set) if it can't be opened
		[[nodiscard]] static std::optional<std::vector<CertificateInfo>> Read(CertificateLocation location, std::wstring const& store);
		// Microsoft's trusted roots, as Windows last downloaded them; nothing if they aren't cached (no update yet, or
		// updates turned off by policy)
		[[nodiscard]] static std::optional<CertificateTrustList> ReadRootProgram();
		// the certificates Microsoft distrusts, as last downloaded
		[[nodiscard]] static std::optional<CertificateTrustList> ReadDisallowed();
		// a CTL's bytes (CertCreateCTLContext): its entries' subject identifiers, the thumbprints
		[[nodiscard]] static std::optional<CertificateTrustList> ParseTrustList(void const* data, size_t size);

		// the stores whose certificates are trusted for something: Root, AuthRoot, CA, TrustedPublisher, TrustedPeople
		[[nodiscard]] static bool IsTrustStore(std::wstring const& store);
		// the stores whose certificates are trust anchors: Root, AuthRoot
		[[nodiscard]] static bool IsRootStore(std::wstring const& store);
		// a root Windows itself installs that Microsoft's program doesn't list: the Insider builds' (".Flight") and two
		// legacy Microsoft roots
		[[nodiscard]] static bool IsWindowsRoot(CertificateInfo const& cert);
		// why the certificate stands out (now: FILETIME); program and disallowed may be null (unknown). A trusted root
		// with its private key here and a trusted certificate Microsoft disallows are dangers; a root neither in the
		// program nor Windows' own is NotInProgram; one added (by its key's write time) to Root, Trusted Publishers or
		// Trusted People in the last RecentDays, unless the program or Windows vouches for it, is Recent; Expired last
		[[nodiscard]] static CertificateAssessment Assess(CertificateInfo const& cert, CertificateTrustList const* program,
			CertificateTrustList const* disallowed, int64_t now);
		[[nodiscard]] static PCWSTR LocationName(CertificateLocation location);	// "Local Machine", "Current User"
	};
}
