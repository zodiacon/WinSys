#include "pch.h"
#include "SystemDetails.h"
#include "SystemInfo.h"
#include "Processes.h"
#include <LM.h>
#include <intrin.h>

#pragma comment(lib, "netapi32")

using namespace WinSys;

namespace {
	std::optional<std::wstring> RegString(HKEY root, PCWSTR key, PCWSTR value) {
		DWORD size = 0;
		if (::RegGetValueW(root, key, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS || size < sizeof(WCHAR))
			return {};
		std::wstring text(size / sizeof(WCHAR), L'\0');
		if (::RegGetValueW(root, key, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, text.data(), &size) != ERROR_SUCCESS)
			return {};
		text.resize(wcslen(text.c_str()));
		return text;
	}

	std::optional<uint32_t> RegDword(HKEY root, PCWSTR key, PCWSTR value) {
		DWORD data = 0, size = sizeof(data);
		if (::RegGetValueW(root, key, value, RRF_RT_REG_DWORD, nullptr, &data, &size) != ERROR_SUCCESS)
			return {};
		return data;
	}

	std::optional<uint64_t> RegQword(HKEY root, PCWSTR key, PCWSTR value) {
		uint64_t data = 0;
		DWORD size = sizeof(data);
		if (::RegGetValueW(root, key, value, RRF_RT_REG_QWORD | RRF_RT_REG_BINARY | RRF_NOEXPAND, nullptr, &data, &size) != ERROR_SUCCESS)
			return {};
		return data;
	}

	std::wstring FromAnsi(std::string_view text) {
		// SMBIOS and CPUID strings are ASCII, padded with spaces
		while (!text.empty() && (text.back() == ' ' || text.back() == '\0'))
			text.remove_suffix(1);
		while (!text.empty() && text.front() == ' ')
			text.remove_prefix(1);
		if (text.empty())
			return {};
		int count = ::MultiByteToWideChar(CP_ACP, 0, text.data(), (int)text.size(), nullptr, 0);
		std::wstring result(count, L'\0');
		::MultiByteToWideChar(CP_ACP, 0, text.data(), (int)text.size(), result.data(), count);
		return result;
	}

	constexpr PCWSTR CurrentVersionKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
}

OsDetails SystemDetails::GetOs() {
	OsDetails os;
	RTL_OSVERSIONINFOEXW version{ sizeof(version) };
	if (NT_SUCCESS(::RtlGetVersion(&version))) {
		os.Major = version.dwMajorVersion;
		os.Minor = version.dwMinorVersion;
		os.Build = version.dwBuildNumber;
	}
	os.Revision = RegDword(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"UBR").value_or(0);
	os.ProductName = RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"ProductName").value_or(L"");
	// Windows 11 kept Windows 10's product name in the key
	if (os.Build >= 22000 && os.ProductName.starts_with(L"Windows 10"))
		os.ProductName.replace(0, 10, L"Windows 11");
	os.EditionId = RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"EditionID").value_or(L"");
	os.DisplayVersion = RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"DisplayVersion").value_or(
		RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"ReleaseId").value_or(L""));
	os.BuildLab = RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"BuildLabEx").value_or(L"");
	os.InstallationType = RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"InstallationType").value_or(L"");
	os.RegisteredOwner = RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"RegisteredOwner").value_or(L"");
	os.RegisteredOrganization = RegString(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"RegisteredOrganization").value_or(L"");
	// InstallTime is a FILETIME (newer builds), InstallDate seconds since 1970; both are of the last feature update
	if (auto time = RegQword(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"InstallTime"))
		os.InstallTime = (int64_t)*time;
	else if (auto date = RegDword(HKEY_LOCAL_MACHINE, CurrentVersionKey, L"InstallDate"))
		os.InstallTime = (int64_t)*date * 10000000LL + 116444736000000000LL;

	SYSTEM_INFO si;
	::GetNativeSystemInfo(&si);
	os.Architecture = si.wProcessorArchitecture;

	if (auto tod = SystemInfo::GetTimeOfDayInformation())
		os.BootTime = tod->BootTime.QuadPart;
	if (auto boot = SystemInfo::GetBootEnvironmentInformation())
		os.FastStartup = boot->DbgHiberBoot;

	WCHAR name[256];
	DWORD size = _countof(name);
	if (::GetComputerNameExW(ComputerNameDnsFullyQualified, name, &size))
		os.ComputerName = name;
	size = _countof(name);
	if (::GetComputerNameExW(ComputerNameNetBIOS, name, &size))
		os.NetBiosName = name;

	PWSTR joinName = nullptr;
	NETSETUP_JOIN_STATUS status;
	if (::NetGetJoinInformation(nullptr, &joinName, &status) == NERR_Success) {
		switch (status) {
			case NetSetupUnjoined: os.Join = DomainJoin::Unjoined; break;
			case NetSetupWorkgroupName: os.Join = DomainJoin::Workgroup; break;
			case NetSetupDomainName: os.Join = DomainJoin::Domain; break;
		}
		if (joinName)
			os.JoinName = joinName;
		::NetApiBufferFree(joinName);
	}

	WCHAR dir[MAX_PATH];
	if (::GetWindowsDirectoryW(dir, _countof(dir)))
		os.WindowsDirectory = dir;

	DYNAMIC_TIME_ZONE_INFORMATION tz;
	if (::GetDynamicTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID)
		os.TimeZone = tz.StandardName;

	WCHAR locale[LOCALE_NAME_MAX_LENGTH];
	if (::GetSystemDefaultLocaleName(locale, _countof(locale)))
		os.SystemLocale = locale;
	if (::GetUserDefaultLocaleName(locale, _countof(locale)))
		os.UserLocale = locale;
	ULONG count = 0, chars = 0;
	if (::GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &count, nullptr, &chars) && chars) {
		std::wstring languages(chars, L'\0');
		if (::GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &count, languages.data(), &chars))
			os.UiLanguage = languages.c_str();	// the first of the list
	}
	return os;
}

SecurityDetails SystemDetails::GetSecurity() {
	SecurityDetails sec;
	if (auto sb = SystemInfo::GetSecureBootInformation()) {
		sec.SecureBootEnabled = sb->SecureBootEnabled != FALSE;
		sec.SecureBootCapable = sb->SecureBootCapable != FALSE;
	}

	if (auto ci = SystemInfo::GetCodeIntegrityInformation()) {
		auto o = ci->CodeIntegrityOptions;
		CodeIntegrity c;
		c.Options = o;
		c.Enabled = o & CODEINTEGRITY_OPTION_ENABLED;
		c.TestSigning = o & CODEINTEGRITY_OPTION_TESTSIGN;
		c.DebugMode = o & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;
		c.FlightSigning = o & CODEINTEGRITY_OPTION_FLIGHTING_ENABLED;
		c.UmciEnforced = (o & CODEINTEGRITY_OPTION_UMCI_ENABLED) && !(o & CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED);
		c.UmciAudit = o & CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED;
		c.HvciEnabled = o & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
		c.HvciAudit = o & CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED;
		c.HvciStrict = o & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED;
		c.WhqlEnforced = o & CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED;
		sec.CodeIntegrity = c;
	}

	if (auto ium = SystemInfo::GetIsolatedUserModeInformation()) {
		VbsState v;
		v.SecureKernelRunning = ium->SecureKernelRunning;
		v.HvciEnabled = ium->HvciEnabled;
		v.HvciStrict = ium->HvciStrictMode;
		v.TrustletsRunning = ium->TrustletRunning;
		v.HardwareEnforced = ium->HardwareEnforcedVbs;
		v.FirmwarePageProtection = ium->FirmwarePageProtection;
		sec.Vbs = v;
	}
	// Credential Guard is the isolated LSA, a trustlet
	for (auto& [pid, name] : Process::EnumProcessNames())
		if (_wcsicmp(name.c_str(), L"LsaIso.exe") == 0) {
			sec.CredentialGuardRunning = true;
			break;
		}

	if (auto kd = SystemInfo::GetKernelDebuggerInformation()) {
		sec.KernelDebuggerEnabled = kd->KernelDebuggerEnabled != FALSE;
		sec.KernelDebuggerAttached = kd->KernelDebuggerEnabled && !kd->KernelDebuggerNotPresent;
	}

	if (auto kva = SystemInfo::GetKernelVaShadowInformation()) {
		sec.KvaShadowEnabled = kva->KvaShadowEnabled != 0;
		if (kva->KvaShadowRequiredAvailable)
			sec.KvaShadowRequired = kva->KvaShadowRequired != 0;
	}

	if (auto spec = SystemInfo::GetSpeculationControlInformation()) {
		auto& f = spec->SpeculationControlFlags;
		SpeculationState s;
		s.BranchTargetMitigation = f.BpbEnabled;
		s.Retpoline = f.SpecCtrlRetpolineEnabled;
		s.EnhancedIbrs = f.EnhancedIbrs;
		s.SsbdSystemWide = f.SpeculativeStoreBypassDisabledSystemWide;
		s.SsbdRequired = f.SpeculativeStoreBypassDisableRequired;
		s.MdsHardwareProtected = f.MdsHardwareProtected;
		s.MdsClearEnabled = f.MbClearEnabled;
		s.BhbEnabled = spec->SpeculationControlFlags2.BhbEnabled;
		sec.Speculation = s;
	}

	if (auto ss = SystemInfo::GetShadowStackInformation()) {
		ShadowStackState s;
		s.Capable = ss->CetCapable;
		s.UserAllowed = ss->UserCetAllowed;
		s.KernelEnabled = ss->KernelCetEnabled;
		s.KernelAudit = ss->KernelCetAuditModeEnabled;
		sec.ShadowStacks = s;
	}

	if (auto dma = SystemInfo::GetDmaGuardPolicyInformation())
		sec.KernelDmaProtection = dma->DmaGuardPolicyEnabled != FALSE;
	if (auto boot = SystemInfo::GetBootEnvironmentInformation())
		sec.MeasuredLaunch = boot->DbgMeasuredLaunch != 0;

	sec.LsaRunAsPpl = RegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL");
	constexpr PCWSTR policies = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
	if (auto lua = RegDword(HKEY_LOCAL_MACHINE, policies, L"EnableLUA"))
		sec.UacEnabled = *lua != 0;
	sec.UacAdminPrompt = RegDword(HKEY_LOCAL_MACHINE, policies, L"ConsentPromptBehaviorAdmin");
	sec.SmartAppControl = RegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"VerifiedAndReputablePolicyState");
	return sec;
}

ProcessorDetails SystemDetails::GetProcessor() {
	ProcessorDetails cpu;
	cpu.Brand = FromAnsi(SystemInfo::GetProcessorBrandString());

#if defined(_M_X64) || defined(_M_IX86)
	int regs[4];
	__cpuid(regs, 0);
	char vendor[13]{};
	memcpy(vendor, &regs[1], 4);
	memcpy(vendor + 4, &regs[3], 4);
	memcpy(vendor + 8, &regs[2], 4);
	cpu.Vendor = FromAnsi(vendor);
	if (regs[0] >= 1) {
		__cpuid(regs, 1);
		uint32_t eax = regs[0];
		uint32_t family = (eax >> 8) & 0xF, model = (eax >> 4) & 0xF;
		if (family == 0xF)
			family += (eax >> 20) & 0xFF;
		if (family == 0x6 || family >= 0xF)
			model += ((eax >> 16) & 0xF) << 4;
		cpu.Family = family;
		cpu.Model = model;
		cpu.Stepping = eax & 0xF;
		cpu.HypervisorPresent = (regs[2] >> 31) & 1;
		if (cpu.HypervisorPresent) {
			__cpuid(regs, 0x40000000);
			char hv[13]{};
			memcpy(hv, &regs[1], 4);
			memcpy(hv + 4, &regs[2], 4);
			memcpy(hv + 8, &regs[3], 4);
			cpu.Hypervisor = FromAnsi(hv);
		}
	}
#endif

	cpu.VirtualizationEnabled = ::IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED);
	cpu.Slat = ::IsProcessorFeaturePresent(PF_SECOND_LEVEL_ADDRESS_TRANSLATION);
	static const struct {
		DWORD Feature;
		PCWSTR Name;
	} features[] = {
		{ PF_XMMI_INSTRUCTIONS_AVAILABLE, L"SSE" }, { PF_XMMI64_INSTRUCTIONS_AVAILABLE, L"SSE2" },
		{ PF_SSE3_INSTRUCTIONS_AVAILABLE, L"SSE3" }, { PF_SSSE3_INSTRUCTIONS_AVAILABLE, L"SSSE3" },
		{ PF_SSE4_1_INSTRUCTIONS_AVAILABLE, L"SSE4.1" }, { PF_SSE4_2_INSTRUCTIONS_AVAILABLE, L"SSE4.2" },
		{ PF_AVX_INSTRUCTIONS_AVAILABLE, L"AVX" }, { PF_AVX2_INSTRUCTIONS_AVAILABLE, L"AVX2" },
		{ PF_AVX512F_INSTRUCTIONS_AVAILABLE, L"AVX-512F" },
		{ PF_RDRAND_INSTRUCTION_AVAILABLE, L"RDRAND" }, { PF_RDTSCP_INSTRUCTION_AVAILABLE, L"RDTSCP" },
		{ PF_RDWRFSGSBASE_AVAILABLE, L"FSGSBASE" }, { PF_COMPARE_EXCHANGE128, L"CMPXCHG16B" },
		{ PF_XSAVE_ENABLED, L"XSAVE" }, { PF_NX_ENABLED, L"NX" }, { PF_FASTFAIL_AVAILABLE, L"FastFail" },
		{ PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, L"ARMv8 Crypto" }, { PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE, L"ARMv8.1 Atomics" },
		{ PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE, L"ARMv8.2 Dot Product" }, { PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE, L"ARMv8.3 JSCVT" },
	};
	for (auto& f : features)
		if (::IsProcessorFeaturePresent(f.Feature))
			cpu.Features.push_back(f.Name);

	uint8_t maxClass = 0;
	bool hybrid = false;
	std::vector<uint8_t> classes;
	for (auto& r : SystemInfo::GetLogicalProcessorAndGroupInformation()) {
		switch (r.Relationship) {
			case RelationProcessorPackage: cpu.Packages++; break;
			case RelationProcessorCore:
				cpu.Cores++;
				classes.push_back(r.EfficiencyClass);
				if (r.EfficiencyClass != classes.front())
					hybrid = true;
				if (r.EfficiencyClass > maxClass)
					maxClass = r.EfficiencyClass;
				break;
			case RelationNumaNode: case RelationNumaNodeEx: cpu.NumaNodes++; break;
			case RelationCache:
				if (r.CacheLevel == 1)
					(r.CacheType == CacheInstruction ? cpu.L1Instruction : cpu.L1Data) += r.CacheSize;
				else if (r.CacheLevel == 2)
					cpu.L2 += r.CacheSize;
				else if (r.CacheLevel == 3)
					cpu.L3 += r.CacheSize;
				break;
			case RelationGroup:
				cpu.Groups = (uint32_t)r.Groups.size();
				for (auto& g : r.Groups)
					cpu.LogicalProcessors += g.ActiveProcessorCount;
				break;
		}
	}
	if (hybrid)
		for (auto c : classes)
			(c == maxClass ? cpu.PerformanceCores : cpu.EfficiencyCores)++;

	constexpr PCWSTR cpuKey = L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
	cpu.RatedMhz = RegDword(HKEY_LOCAL_MACHINE, cpuKey, L"~MHz").value_or(0);
	// Intel keeps the revision in the upper half, AMD in the lower
	if (auto rev = RegQword(HKEY_LOCAL_MACHINE, cpuKey, L"Update Revision"); rev && *rev) {
		auto v = *rev;
		cpu.Microcode = (uint32_t)((v & 0xFFFFFFFF) == 0 ? v >> 32 : v);
	}
	return cpu;
}

namespace {
	// a structure's strings follow its formatted area, numbered from 1, ending with two nulls
	struct SmbiosStructure {
		const uint8_t* Data;
		uint8_t Length;
		std::vector<std::string_view> Strings;

		uint8_t Byte(size_t offset) const {
			return offset < Length ? Data[offset] : 0;
		}
		uint16_t Word(size_t offset) const {
			return offset + 2 <= Length ? *(const uint16_t*)(Data + offset) : 0;
		}
		uint32_t Dword(size_t offset) const {
			return offset + 4 <= Length ? *(const uint32_t*)(Data + offset) : 0;
		}
		std::wstring String(size_t offset) const {
			auto index = Byte(offset);
			if (!index || index > Strings.size())
				return {};
			auto text = FromAnsi(Strings[index - 1]);
			// what boards ship with for strings nobody filled in
			static const PCWSTR placeholders[] = {
				L"Default string", L"To Be Filled By O.E.M.", L"To be filled by O.E.M.", L"Not Specified", L"Not Applicable",
				L"System Product Name", L"System manufacturer", L"System Version", L"Unknown", L"None", L"N/A", L"0123456789",
			};
			for (auto p : placeholders)
				if (_wcsicmp(text.c_str(), p) == 0)
					return {};
			return text;
		}
	};

	PCWSTR MemoryTypeName(uint8_t type) {
		switch (type) {
			case 0x03: return L"DRAM";
			case 0x0F: return L"SDRAM";
			case 0x11: return L"RDRAM";
			case 0x12: return L"DDR";
			case 0x13: return L"DDR2";
			case 0x14: return L"DDR2 FB-DIMM";
			case 0x18: return L"DDR3";
			case 0x19: return L"FBD2";
			case 0x1A: return L"DDR4";
			case 0x1B: return L"LPDDR";
			case 0x1C: return L"LPDDR2";
			case 0x1D: return L"LPDDR3";
			case 0x1E: return L"LPDDR4";
			case 0x1F: return L"Logical non-volatile";
			case 0x20: return L"HBM";
			case 0x21: return L"HBM2";
			case 0x22: return L"DDR5";
			case 0x23: return L"LPDDR5";
			case 0x24: return L"HBM3";
		}
		return L"";
	}

	PCWSTR FormFactorName(uint8_t ff) {
		switch (ff) {
			case 0x03: return L"SIMM";
			case 0x07: return L"SIP";
			case 0x08: return L"Chip";
			case 0x09: return L"DIMM";
			case 0x0B: return L"Row of chips";
			case 0x0C: return L"RIMM";
			case 0x0D: return L"SODIMM";
			case 0x0F: return L"FB-DIMM";
			case 0x10: return L"Die";
			case 0x11: return L"CAMM";
		}
		return L"";
	}
}

HardwareDetails SystemDetails::GetHardware() {
	HardwareDetails hw;
	ULONGLONG installedKB = 0;
	if (::GetPhysicallyInstalledSystemMemory(&installedKB))
		hw.InstalledMemory = installedKB * 1024;
	if (auto basic = SystemInfo::GetBasicInformation())
		hw.UsableMemory = (uint64_t)basic->NumberOfPhysicalPages * basic->PageSize;

	constexpr DWORD rsmb = 'RSMB';
	auto size = ::GetSystemFirmwareTable(rsmb, 0, nullptr, 0);
	if (size < 8)
		return hw;
	std::vector<uint8_t> buffer(size);
	if (::GetSystemFirmwareTable(rsmb, 0, buffer.data(), size) != size)
		return hw;

	// RawSMBIOSData: calling method, major, minor, DMI revision, length, the tables
	hw.SmbiosMajor = buffer[1];
	hw.SmbiosMinor = buffer[2];
	auto length = *(const uint32_t*)(buffer.data() + 4);
	const uint8_t* p = buffer.data() + 8;
	const uint8_t* end = p + (length < size - 8 ? length : size - 8);
	while (p + 4 <= end) {
		SmbiosStructure s{ p, p[1] };
		if (s.Length < 4 || p + s.Length > end)
			break;
		// the strings
		auto q = (const char*)(p + s.Length);
		auto qend = (const char*)end;
		while (q < qend && *q) {
			auto len = strnlen(q, qend - q);
			s.Strings.emplace_back(q, len);
			q += len + 1;
		}
		auto next = (const uint8_t*)(q < qend && !*q && q == (const char*)(p + s.Length) ? q + 2 : q + 1);
		uint8_t type = p[0];

		switch (type) {
			case 0:		// BIOS
				hw.BiosVendor = s.String(0x04);
				hw.BiosVersion = s.String(0x05);
				hw.BiosDate = s.String(0x08);
				break;
			case 1:		// system
				hw.SystemManufacturer = s.String(0x04);
				hw.SystemProduct = s.String(0x05);
				hw.SystemVersion = s.String(0x06);
				hw.SystemSku = s.String(0x19);
				hw.SystemFamily = s.String(0x1A);
				break;
			case 2:		// baseboard
				if (hw.BoardManufacturer.empty() && hw.BoardProduct.empty()) {
					hw.BoardManufacturer = s.String(0x04);
					hw.BoardProduct = s.String(0x05);
					hw.BoardVersion = s.String(0x06);
				}
				break;
			case 16:	// physical memory array: system memory only
				if (s.Byte(0x05) == 0x03)
					hw.MemorySlots += s.Word(0x0D);
				break;
			case 17:	// memory device
			{
				uint64_t bytes = 0;
				auto sz = s.Word(0x0C);
				if (sz == 0 || sz == 0xFFFF)
					break;		// empty slot, or unknown
				if (sz == 0x7FFF)
					bytes = (uint64_t)(s.Dword(0x1C) & 0x7FFFFFFF) << 20;
				else if (sz & 0x8000)
					bytes = (uint64_t)(sz & 0x7FFF) << 10;
				else
					bytes = (uint64_t)sz << 20;
				MemoryModule m;
				m.Size = bytes;
				m.FormFactor = FormFactorName(s.Byte(0x0E));
				m.Locator = s.String(0x10);
				m.BankLocator = s.String(0x11);
				m.Type = MemoryTypeName(s.Byte(0x12));
				m.Speed = s.Word(0x15);
				if (m.Speed == 0xFFFF)
					m.Speed = s.Dword(0x54);
				m.Manufacturer = s.String(0x17);
				m.PartNumber = s.String(0x1A);
				m.ConfiguredSpeed = s.Word(0x20);
				if (m.ConfiguredSpeed == 0xFFFF)
					m.ConfiguredSpeed = s.Dword(0x58);
				hw.Modules.push_back(std::move(m));
				break;
			}
		}
		if (type == 127)	// end of table
			break;
		p = next;
	}
	return hw;
}
