#include "pch.h"
#include "Packages.h"
#include <roapi.h>
#include <wrl/client.h>
#include <wrl/wrappers/corewrappers.h>
#include <windows.foundation.collections.h>
#include <windows.applicationmodel.h>
#include <windows.management.deployment.h>
#include <appmodel.h>
#include <shobjidl_core.h>

#pragma comment(lib, "runtimeobject")

using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Wrappers::HStringReference;
using Microsoft::WRL::Wrappers::HString;
namespace Model = ABI::Windows::ApplicationModel;
namespace Deployment = ABI::Windows::Management::Deployment;
namespace Collections = ABI::Windows::Foundation::Collections;

namespace WinSys {
	namespace {
		std::wstring ToString(HSTRING s) {
			UINT32 length = 0;
			auto buffer = ::WindowsGetStringRawBuffer(s, &length);
			return std::wstring(buffer ? buffer : L"", length);
		}

		// a string property: the HSTRING it returns, freed
		template<typename T, typename F>
		std::wstring GetString(T* object, F getter) {
			HString value;
			if (object && SUCCEEDED((object->*getter)(value.GetAddressOf())))
				return ToString(value.Get());
			return L"";
		}

		template<typename T, typename F>
		bool GetBool(T* object, F getter) {
			boolean value = false;
			return object && SUCCEEDED((object->*getter)(&value)) && value;
		}

		PackageProblem GetProblems(Model::IPackageStatus* status) {
			using S = Model::IPackageStatus;
			static const struct {
				HRESULT(STDMETHODCALLTYPE S::* Getter)(boolean*);
				PackageProblem Problem;
			} checks[] = {
				{ &S::get_NotAvailable, PackageProblem::NotAvailable },
				{ &S::get_PackageOffline, PackageProblem::PackageOffline },
				{ &S::get_DataOffline, PackageProblem::DataOffline },
				{ &S::get_Disabled, PackageProblem::Disabled },
				{ &S::get_NeedsRemediation, PackageProblem::NeedsRemediation },
				{ &S::get_LicenseIssue, PackageProblem::LicenseIssue },
				{ &S::get_Modified, PackageProblem::Modified },
				{ &S::get_Tampered, PackageProblem::Tampered },
				{ &S::get_DependencyIssue, PackageProblem::DependencyIssue },
				{ &S::get_Servicing, PackageProblem::Servicing },
				{ &S::get_DeploymentInProgress, PackageProblem::DeploymentInProgress },
			};
			auto problems = PackageProblem::None;
			if (!status || GetBool(status, &S::VerifyIsOK))
				return problems;
			for (auto& check : checks)
				if (GetBool(status, check.Getter))
					problems = problems | check.Problem;
			return problems;
		}

		PackageInfo Describe(Model::IPackage* package) {
			PackageInfo info;
			ComPtr<Model::IPackageId> id;
			if (SUCCEEDED(package->get_Id(&id))) {
				info.Name = GetString(id.Get(), &Model::IPackageId::get_Name);
				info.FullName = GetString(id.Get(), &Model::IPackageId::get_FullName);
				info.FamilyName = GetString(id.Get(), &Model::IPackageId::get_FamilyName);
				info.Publisher = GetString(id.Get(), &Model::IPackageId::get_Publisher);
				info.PublisherId = GetString(id.Get(), &Model::IPackageId::get_PublisherId);
				info.ResourceId = GetString(id.Get(), &Model::IPackageId::get_ResourceId);
				Model::PackageVersion version{};
				if (SUCCEEDED(id->get_Version(&version)))
					info.Version = (uint64_t(version.Major) << 48) | (uint64_t(version.Minor) << 32) | (uint64_t(version.Build) << 16) | version.Revision;
				ABI::Windows::System::ProcessorArchitecture arch{};
				if (SUCCEEDED(id->get_Architecture(&arch)))
					info.Architecture = (uint32_t)arch;
			}
			info.Framework = GetBool(package, &Model::IPackage::get_IsFramework);

			// each newer interface is looked for: older Windows versions lack some
			ComPtr<Model::IPackage2> package2;
			if (SUCCEEDED(package->QueryInterface(IID_PPV_ARGS(&package2)))) {
				info.DisplayName = GetString(package2.Get(), &Model::IPackage2::get_DisplayName);
				info.PublisherDisplayName = GetString(package2.Get(), &Model::IPackage2::get_PublisherDisplayName);
				info.Description = GetString(package2.Get(), &Model::IPackage2::get_Description);
				info.Resource = GetBool(package2.Get(), &Model::IPackage2::get_IsResourcePackage);
				info.Bundle = GetBool(package2.Get(), &Model::IPackage2::get_IsBundle);
				info.DevelopmentMode = GetBool(package2.Get(), &Model::IPackage2::get_IsDevelopmentMode);
			}
			ComPtr<Model::IPackage3> package3;
			if (SUCCEEDED(package->QueryInterface(IID_PPV_ARGS(&package3)))) {
				ComPtr<Model::IPackageStatus> status;
				if (SUCCEEDED(package3->get_Status(&status)))
					info.Problems = GetProblems(status.Get());
				ABI::Windows::Foundation::DateTime date{};
				if (SUCCEEDED(package3->get_InstalledDate(&date)))
					info.InstalledDate = date.UniversalTime;
			}
			ComPtr<Model::IPackage4> package4;
			if (SUCCEEDED(package->QueryInterface(IID_PPV_ARGS(&package4)))) {
				Model::PackageSignatureKind kind{};
				if (SUCCEEDED(package4->get_SignatureKind(&kind)))
					info.Signature = (PackageSignature)kind;
				info.Optional = GetBool(package4.Get(), &Model::IPackage4::get_IsOptional);
			}
			ComPtr<Model::IPackage8> package8;
			if (SUCCEEDED(package->QueryInterface(IID_PPV_ARGS(&package8))))
				info.InstalledPath = GetString(package8.Get(), &Model::IPackage8::get_InstalledPath);

			ComPtr<Collections::IVectorView<Model::Package*>> dependencies;
			if (SUCCEEDED(package->get_Dependencies(&dependencies))) {
				unsigned count = 0;
				dependencies->get_Size(&count);
				for (unsigned i = 0; i < count; i++) {
					ComPtr<Model::IPackage> dependency;
					ComPtr<Model::IPackageId> dependencyId;
					if (SUCCEEDED(dependencies->GetAt(i, &dependency)) && SUCCEEDED(dependency->get_Id(&dependencyId)))
						info.Dependencies.push_back(GetString(dependencyId.Get(), &Model::IPackageId::get_FullName));
				}
			}
			return info;
		}
	}

	std::optional<std::vector<PackageInfo>> Packages::Enum(bool allUsers) {
		ComPtr<Deployment::IPackageManager> manager;
		auto hr = ::RoActivateInstance(HStringReference(RuntimeClass_Windows_Management_Deployment_PackageManager).Get(), &manager);
		if (FAILED(hr)) {
			::SetLastError(hr);
			return {};
		}
		ComPtr<Collections::IIterable<Model::Package*>> packages;
		hr = allUsers ? manager->FindPackages(&packages)
			: manager->FindPackagesByUserSecurityId(HStringReference(L"").Get(), &packages);
		if (FAILED(hr)) {
			::SetLastError(hr);
			return {};
		}
		std::vector<PackageInfo> result;
		ComPtr<Collections::IIterator<Model::Package*>> it;
		if (FAILED(hr = packages->First(&it))) {
			::SetLastError(hr);
			return {};
		}
		boolean has = false;
		for (it->get_HasCurrent(&has); has; it->MoveNext(&has)) {
			ComPtr<Model::IPackage> package;
			if (SUCCEEDED(it->get_Current(&package)))
				result.push_back(Describe(package.Get()));
		}
		return result;
	}

	std::vector<std::wstring> Packages::GetApplicationIds(std::wstring const& fullName) {
		std::vector<std::wstring> ids;
		PACKAGE_INFO_REFERENCE info{};
		if (::OpenPackageInfoByFullName(fullName.c_str(), 0, &info) != ERROR_SUCCESS)
			return ids;
		// the buffer holds the strings' pointers, then the strings
		UINT32 size = 0, count = 0;
		if (::GetPackageApplicationIds(info, &size, nullptr, &count) == ERROR_INSUFFICIENT_BUFFER && size > 0) {
			std::vector<BYTE> buffer(size);
			if (::GetPackageApplicationIds(info, &size, buffer.data(), &count) == ERROR_SUCCESS) {
				auto names = reinterpret_cast<PCWSTR const*>(buffer.data());
				for (UINT32 i = 0; i < count; i++)
					ids.push_back(names[i]);
			}
		}
		::ClosePackageInfo(info);
		return ids;
	}

	uint32_t Packages::Launch(std::wstring const& appUserModelId) {
		ComPtr<IApplicationActivationManager> manager;
		auto hr = ::CoCreateInstance(CLSID_ApplicationActivationManager, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&manager));
		DWORD pid = 0;
		if (SUCCEEDED(hr))
			hr = manager->ActivateApplication(appUserModelId.c_str(), nullptr, AO_NONE, &pid);
		if (FAILED(hr)) {
			::SetLastError(hr);
			return 0;
		}
		return pid;
	}

	std::wstring Packages::AppIdOf(std::wstring const& appUserModelId) {
		auto bang = appUserModelId.find(L'!');
		return bang == std::wstring::npos ? appUserModelId : appUserModelId.substr(bang + 1);
	}

	std::wstring Packages::VersionText(uint64_t version) {
		return std::to_wstring(version >> 48) + L"." + std::to_wstring((version >> 32) & 0xffff) + L"." +
			std::to_wstring((version >> 16) & 0xffff) + L"." + std::to_wstring(version & 0xffff);
	}

	std::wstring Packages::ArchitectureText(uint32_t architecture) {
		switch (architecture) {
			case 0: return L"x86";
			case 5: return L"ARM";
			case 9: return L"x64";
			case 11: return L"Neutral";
			case 12: return L"ARM64";
			case 14: return L"x86 on ARM64";
			case 65535: return L"Unknown";
		}
		return std::to_wstring(architecture);
	}

	PCWSTR Packages::SignatureText(PackageSignature signature) {
		switch (signature) {
			case PackageSignature::None: return L"None";
			case PackageSignature::Developer: return L"Developer";
			case PackageSignature::Enterprise: return L"Enterprise";
			case PackageSignature::Store: return L"Store";
			case PackageSignature::System: return L"System";
		}
		return L"";
	}

	std::wstring Packages::ProblemsText(PackageProblem problems) {
		static const struct {
			PackageProblem Problem;
			PCWSTR Text;
		} names[] = {
			{ PackageProblem::NotAvailable, L"Not available" },
			{ PackageProblem::PackageOffline, L"Package offline" },
			{ PackageProblem::DataOffline, L"Data offline" },
			{ PackageProblem::Disabled, L"Disabled" },
			{ PackageProblem::NeedsRemediation, L"Needs remediation" },
			{ PackageProblem::LicenseIssue, L"License issue" },
			{ PackageProblem::Modified, L"Modified" },
			{ PackageProblem::Tampered, L"Tampered" },
			{ PackageProblem::DependencyIssue, L"Dependency issue" },
			{ PackageProblem::Servicing, L"Servicing" },
			{ PackageProblem::DeploymentInProgress, L"Deployment in progress" },
		};
		if (problems == PackageProblem::None)
			return L"OK";
		std::wstring text;
		for (auto& name : names)
			if (problems & name.Problem) {
				if (!text.empty())
					text += L", ";
				text += name.Text;
			}
		return text;
	}

	PCWSTR Packages::KindText(PackageInfo const& package) {
		if (package.Bundle)
			return L"Bundle";
		if (package.Framework)
			return L"Framework";
		if (package.Resource)
			return L"Resource";
		if (package.Optional)
			return L"Optional";
		return L"Main";
	}
}
