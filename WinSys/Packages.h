#pragma once

#include <vector>
#include <optional>
#include <string>

namespace WinSys {
	// what's wrong with a package (Package.Status); None when it's OK
	enum class PackageProblem : uint32_t {
		None = 0,
		NotAvailable = 1 << 0,
		PackageOffline = 1 << 1,
		DataOffline = 1 << 2,
		Disabled = 1 << 3,
		NeedsRemediation = 1 << 4,
		LicenseIssue = 1 << 5,
		Modified = 1 << 6,
		Tampered = 1 << 7,
		DependencyIssue = 1 << 8,
		Servicing = 1 << 9,
		DeploymentInProgress = 1 << 10,
	};
	inline PackageProblem operator|(PackageProblem a, PackageProblem b) {
		return PackageProblem((uint32_t)a | (uint32_t)b);
	}
	inline bool operator&(PackageProblem a, PackageProblem b) {
		return ((uint32_t)a & (uint32_t)b) != 0;
	}

	// Package.SignatureKind's values
	enum class PackageSignature {
		None, Developer, Enterprise, Store, System,
	};

	struct PackageInfo {
		std::wstring FullName, FamilyName, Name, Publisher, PublisherId, ResourceId;
		std::wstring DisplayName, PublisherDisplayName, Description;	// from the manifest, localized; may be empty
		std::wstring InstalledPath;
		uint64_t Version{ 0 };		// major, minor, build, revision: 16 bits each, major highest
		uint32_t Architecture{ 0 };	// Windows.System.ProcessorArchitecture (X86 0, Arm 5, X64 9, Neutral 11, Arm64 12...)
		int64_t InstalledDate{ 0 };	// FILETIME units; 0 if unknown
		PackageSignature Signature{ PackageSignature::None };
		PackageProblem Problems{ PackageProblem::None };
		bool Framework{ false }, Resource{ false }, Bundle{ false }, Optional{ false }, DevelopmentMode{ false };
		std::vector<std::wstring> Dependencies;	// the full names of the packages it depends on
	};

	//
	// The installed packages (MSIX/AppX), from the Windows Runtime's PackageManager through its ABI (WRL; COM must be
	// initialized on the calling thread): the current user's (FindPackagesByUserSecurityId with an empty SID), or every
	// user's (FindPackages, which needs elevation: E_ACCESSDENIED otherwise). Main packages, frameworks, resource and
	// optional packages and bundles alike; nothing on failure, with the last error set (the HRESULT).
	//
	struct Packages final {
		[[nodiscard]] static std::optional<std::vector<PackageInfo>> Enum(bool allUsers = false);

		// the package's applications as app user model IDs ("<family name>!<app ID>"), from its manifest
		// (GetPackageApplicationIds); empty for a package without any (frameworks, resources) or one that isn't
		// installed for the caller
		[[nodiscard]] static std::vector<std::wstring> GetApplicationIds(std::wstring const& fullName);
		// starts an application by its app user model ID (IApplicationActivationManager, as the Start menu does; COM
		// must be initialized on the calling thread): its process ID, or 0 with the last error set (the HRESULT)
		[[nodiscard]] static uint32_t Launch(std::wstring const& appUserModelId);
		// the application ID in an app user model ID (the part after '!')
		[[nodiscard]] static std::wstring AppIdOf(std::wstring const& appUserModelId);

		// "1.2.3.4"
		[[nodiscard]] static std::wstring VersionText(uint64_t version);
		// "x64", "Neutral"...
		[[nodiscard]] static std::wstring ArchitectureText(uint32_t architecture);
		[[nodiscard]] static PCWSTR SignatureText(PackageSignature signature);
		// "OK", or the problems in words, comma separated
		[[nodiscard]] static std::wstring ProblemsText(PackageProblem problems);
		// "Framework", "Resource", "Bundle", "Optional" or "Main"
		[[nodiscard]] static PCWSTR KindText(PackageInfo const& package);
	};
}
