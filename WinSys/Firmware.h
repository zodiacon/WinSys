#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// Read-only views of the firmware and the TPM:
// - The UEFI variables (NtEnumerateSystemEnvironmentValuesEx), which need SeSystemEnvironmentPrivilege (an elevated
//   token has it; it's enabled for the call), and what they say about booting: the boot entries (Boot####, in BootOrder,
//   with BootCurrent and BootNext), the timeout and Secure Boot.
// - The TPM, through TBS: its version and interface (Tbsi_GetDeviceInfo), and its identity from TPM2_GetCapability's
//   fixed properties (manufacturer, vendor string, firmware version, specification revision).
//

namespace WinSys {
	enum class FirmwareType {
		Unknown,
		Bios,
		Uefi,
	};

	struct UefiVariable {
		std::wstring Name;
		GUID Vendor{};
		uint32_t Attributes{ 0 };	// EFI_VARIABLE_*
		std::vector<uint8_t> Value;
	};

	struct BootEntry {
		uint16_t Number{ 0 };		// the #### of its Boot#### variable
		std::wstring Description;
		uint32_t Attributes{ 0 };	// LOAD_OPTION_*: 1 active, 8 hidden
		std::wstring FilePath;		// the device path's file path node, if it has one (an EFI application)
		int Order{ -1 };			// its position in BootOrder; -1 if it isn't there
	};

	struct BootConfiguration {
		std::vector<BootEntry> Entries;	// in BootOrder's order, then the others by number
		std::optional<uint16_t> Current, Next, Timeout;	// BootCurrent, BootNext, Timeout (seconds)
		std::optional<bool> SecureBoot, SetupMode;
	};

	struct TpmInfo {
		bool Present{ false };
		uint32_t Version{ 0 };	// 1 (1.2) or 2 (2.0), from TBS
		uint32_t InterfaceType{ 0 };	// TPM_IFTYPE_*
		uint32_t ImplementationRevision{ 0 };
		// TPM 2.0's fixed properties; empty or 0 when they couldn't be read
		std::wstring Manufacturer;	// four characters, such as "INTC", "AMD ", "MSFT"
		std::wstring VendorString;
		std::wstring Family;		// "2.0"
		uint32_t Level{ 0 }, Revision{ 0 };	// the specification's level and revision (x100: 159 is 1.59)
		uint32_t Year{ 0 }, DayOfYear{ 0 };	// the specification's date
		uint32_t FirmwareVersion1{ 0 }, FirmwareVersion2{ 0 };
		uint32_t Error{ 0 };	// a TBS error, if the TPM couldn't be queried
	};

	struct Firmware final {
		[[nodiscard]] static FirmwareType GetType();
		// every UEFI variable with its value; nothing on failure, with the last error (ERROR_PRIVILEGE_NOT_HELD when not
		// elevated, ERROR_INVALID_FUNCTION on a BIOS system)
		[[nodiscard]] static std::optional<std::vector<UefiVariable>> EnumVariables();
		// the boot entries and settings, from the variables EnumVariables gave
		[[nodiscard]] static BootConfiguration GetBootConfiguration(std::vector<UefiVariable> const& variables);
		// the EFI global variables' vendor ({8BE4DF61-93CA-11D2-AA0D-00E098032B8C})
		[[nodiscard]] static GUID const& GlobalVariableVendor();
	};

	struct Tpm final {
		[[nodiscard]] static TpmInfo GetInfo();
	};
}
