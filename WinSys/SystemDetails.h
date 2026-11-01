#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// What a System Information page shows, decoded, in plain types (no native API headers needed):
// - OsDetails: the version (RtlGetVersion and the CurrentVersion key's names, UBR included), installation and boot
//   times, the computer's name and domain or workgroup (NetGetJoinInformation), time zone and locales.
// - SecurityDetails: Secure Boot, code integrity (SystemCodeIntegrityInformation's options), virtualization-based
//   security (SystemIsolatedUserModeInformation; Credential Guard as LsaIso.exe running), the kernel debugger, kernel
//   VA shadow, the speculation control mitigations, kernel shadow stacks (CET), Kernel DMA Protection, System Guard's
//   measured launch, LSA protection, UAC and Smart App Control (their registry values). Each value is optional:
//   empty when its query failed (an older Windows, or no access).
// - ProcessorDetails: CPUID's vendor, family, model and stepping, the features Windows reports
//   (IsProcessorFeaturePresent), the topology (packages, cores, logical processors, NUMA nodes, caches;
//   GetLogicalProcessorInformationEx), the microcode revision and rated speed (the CentralProcessor key) and the
//   hypervisor (CPUID leaf 0x40000000).
// - HardwareDetails: the SMBIOS tables (GetSystemFirmwareTable 'RSMB'): BIOS, system and baseboard, and the memory
//   devices (type 17) with their sizes, types and speeds; and the installed and usable memory.
// None needs elevation.
//

namespace WinSys {
	enum class DomainJoin {
		Unknown,
		Unjoined,
		Workgroup,
		Domain,
	};

	struct OsDetails {
		std::wstring ProductName;		// "Windows 11 Pro" (the key says Windows 10 on 11; corrected by build)
		std::wstring EditionId;			// "Professional"
		std::wstring DisplayVersion;	// "24H2"
		std::wstring BuildLab;			// BuildLabEx
		std::wstring InstallationType;	// "Client", "Server"...
		uint32_t Major{ 0 }, Minor{ 0 }, Build{ 0 }, Revision{ 0 };	// Revision: UBR
		uint16_t Architecture{ 0 };		// the native PROCESSOR_ARCHITECTURE_*
		int64_t InstallTime{ 0 };		// FILETIME; 0 if unknown
		int64_t BootTime{ 0 };			// FILETIME
		bool FastStartup{ false };		// this boot resumed a hibernated kernel (hybrid boot)
		std::wstring RegisteredOwner, RegisteredOrganization;
		std::wstring ComputerName;		// the DNS name, fully qualified
		std::wstring NetBiosName;
		DomainJoin Join{ DomainJoin::Unknown };
		std::wstring JoinName;			// the domain or workgroup
		std::wstring WindowsDirectory;
		std::wstring TimeZone;			// its standard name
		std::wstring SystemLocale, UserLocale;	// "en-US"
		std::wstring UiLanguage;		// the user's preferred UI language
	};

	struct CodeIntegrity {
		bool Enabled{ false };
		bool TestSigning{ false };
		bool DebugMode{ false };
		bool FlightSigning{ false };
		bool UmciEnforced{ false }, UmciAudit{ false };	// user-mode code integrity (App Control for Business)
		bool HvciEnabled{ false }, HvciAudit{ false }, HvciStrict{ false };	// memory integrity
		bool WhqlEnforced{ false };
		uint32_t Options{ 0 };			// CODEINTEGRITY_OPTION_*
	};

	struct VbsState {
		bool SecureKernelRunning{ false };
		bool HvciEnabled{ false }, HvciStrict{ false };
		bool TrustletsRunning{ false };
		bool HardwareEnforced{ false };
		bool FirmwarePageProtection{ false };
	};

	struct SpeculationState {
		bool BranchTargetMitigation{ false };	// BpbEnabled (Spectre v2)
		bool Retpoline{ false };
		bool EnhancedIbrs{ false };
		bool SsbdSystemWide{ false };			// speculative store bypass disabled system-wide
		bool SsbdRequired{ false };
		bool MdsHardwareProtected{ false };
		bool MdsClearEnabled{ false };			// MbClearEnabled
		bool BhbEnabled{ false };				// branch history buffer mitigation
	};

	struct ShadowStackState {
		bool Capable{ false };
		bool UserAllowed{ false };
		bool KernelEnabled{ false };
		bool KernelAudit{ false };
	};

	struct SecurityDetails {
		std::optional<bool> SecureBootEnabled, SecureBootCapable;
		std::optional<CodeIntegrity> CodeIntegrity;
		std::optional<VbsState> Vbs;
		bool CredentialGuardRunning{ false };	// LsaIso.exe, the isolated LSA, is running
		std::optional<bool> KernelDebuggerEnabled, KernelDebuggerAttached;
		std::optional<bool> KvaShadowEnabled, KvaShadowRequired;
		std::optional<SpeculationState> Speculation;
		std::optional<ShadowStackState> ShadowStacks;
		std::optional<bool> KernelDmaProtection;
		std::optional<bool> MeasuredLaunch;		// System Guard Secure Launch, this boot
		std::optional<uint32_t> LsaRunAsPpl;	// the Lsa key's RunAsPPL: 1 with a UEFI lock, 2 without
		std::optional<bool> UacEnabled;			// EnableLUA
		std::optional<uint32_t> UacAdminPrompt;	// ConsentPromptBehaviorAdmin (0-5)
		std::optional<uint32_t> SmartAppControl;	// VerifiedAndReputablePolicyState: 0 off, 1 on, 2 evaluation
	};

	struct ProcessorDetails {
		std::wstring Brand;
		std::wstring Vendor;			// "GenuineIntel", "AuthenticAMD"; empty without CPUID
		uint32_t Family{ 0 }, Model{ 0 }, Stepping{ 0 };	// with CPUID's extended family and model added in
		uint32_t Packages{ 0 }, Cores{ 0 }, LogicalProcessors{ 0 }, Groups{ 0 }, NumaNodes{ 0 };
		uint32_t PerformanceCores{ 0 }, EfficiencyCores{ 0 };	// both zero unless the processor is hybrid
		uint64_t L1Data{ 0 }, L1Instruction{ 0 }, L2{ 0 }, L3{ 0 };	// bytes, all instances together
		uint32_t RatedMhz{ 0 };
		std::optional<uint32_t> Microcode;
		bool HypervisorPresent{ false };
		std::wstring Hypervisor;		// its CPUID vendor ("Microsoft Hv")
		bool VirtualizationEnabled{ false };	// in the firmware (PF_VIRT_FIRMWARE_ENABLED)
		bool Slat{ false };				// second-level address translation
		std::vector<std::wstring> Features;	// the instruction set extensions Windows reports present
	};

	struct MemoryModule {
		std::wstring Locator, BankLocator;
		std::wstring Manufacturer, PartNumber;
		std::wstring Type, FormFactor;	// "DDR5", "SODIMM"
		uint64_t Size{ 0 };				// bytes
		uint32_t Speed{ 0 }, ConfiguredSpeed{ 0 };	// MT/s; 0 if unknown
	};

	struct HardwareDetails {
		uint8_t SmbiosMajor{ 0 }, SmbiosMinor{ 0 };	// 0 when there are no SMBIOS tables
		std::wstring SystemManufacturer, SystemProduct, SystemVersion, SystemFamily, SystemSku;
		std::wstring BiosVendor, BiosVersion, BiosDate;
		std::wstring BoardManufacturer, BoardProduct, BoardVersion;
		uint64_t InstalledMemory{ 0 };	// bytes (GetPhysicallyInstalledSystemMemory)
		uint64_t UsableMemory{ 0 };		// bytes the OS manages
		uint32_t MemorySlots{ 0 };		// type 16's device counts added up
		std::vector<MemoryModule> Modules;	// populated slots only
	};

	struct SystemDetails final {
		[[nodiscard]] static OsDetails GetOs();
		[[nodiscard]] static SecurityDetails GetSecurity();
		[[nodiscard]] static ProcessorDetails GetProcessor();
		[[nodiscard]] static HardwareDetails GetHardware();
	};
}
