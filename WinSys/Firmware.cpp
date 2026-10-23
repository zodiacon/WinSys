#include "pch.h"
#include "Firmware.h"
#include "SecurityHelper.h"
#include <tbs.h>
#include <algorithm>

#pragma comment(lib, "tbs")

using namespace WinSys;

namespace {
	const GUID EfiGlobalVariable = { 0x8be4df61, 0x93ca, 0x11d2, { 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c } };

	UefiVariable const* FindGlobal(std::vector<UefiVariable> const& variables, PCWSTR name) {
		auto it = std::ranges::find_if(variables, [&](auto& v) { return ::IsEqualGUID(v.Vendor, EfiGlobalVariable) && v.Name == name; });
		return it == variables.end() ? nullptr : &*it;
	}

	std::optional<uint16_t> GetUInt16(std::vector<UefiVariable> const& variables, PCWSTR name) {
		auto v = FindGlobal(variables, name);
		if (!v || v->Value.size() < sizeof(uint16_t))
			return std::nullopt;
		uint16_t value;
		memcpy(&value, v->Value.data(), sizeof(value));
		return value;
	}

	std::optional<bool> GetFlag(std::vector<UefiVariable> const& variables, PCWSTR name) {
		auto v = FindGlobal(variables, name);
		if (!v || v->Value.empty())
			return std::nullopt;
		return v->Value[0] != 0;
	}

	// an EFI_LOAD_OPTION: Attributes (UINT32), FilePathListLength (UINT16), Description (CHAR16, null-terminated), then
	// the device path nodes (Type, SubType, Length), the media file path node (4, 4) holding a CHAR16 path
	bool ParseLoadOption(std::vector<uint8_t> const& data, BootEntry& entry) {
		if (data.size() < 6)
			return false;
		memcpy(&entry.Attributes, data.data(), sizeof(uint32_t));
		uint16_t pathLength;
		memcpy(&pathLength, data.data() + 4, sizeof(uint16_t));
		size_t offset = 6;
		while (offset + 1 < data.size()) {
			wchar_t c;
			memcpy(&c, data.data() + offset, sizeof(c));
			offset += sizeof(wchar_t);
			if (c == 0)
				break;
			entry.Description += c;
		}
		size_t end = (std::min)(data.size(), offset + pathLength);
		while (offset + 4 <= end) {
			uint8_t type = data[offset], subType = data[offset + 1];
			uint16_t length;
			memcpy(&length, data.data() + offset + 2, sizeof(length));
			if (length < 4 || offset + length > end || type == 0x7f)	// the end node
				break;
			if (type == 4 && subType == 4) {
				std::wstring path((length - 4) / sizeof(wchar_t), L'\0');
				memcpy(path.data(), data.data() + offset + 4, path.size() * sizeof(wchar_t));
				path.resize(::wcsnlen(path.c_str(), path.size()));
				entry.FilePath += path;
			}
			offset += length;
		}
		return true;
	}

	// TPM 2.0 values are big-endian
	uint32_t ReadUInt32(BYTE const* p) {
		return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
	}

	std::wstring FourChars(uint32_t value) {
		std::wstring text;
		for (int shift = 24; shift >= 0; shift -= 8)
			if (auto c = (wchar_t)((value >> shift) & 0xff); c >= 0x20 && c < 0x7f)
				text += c;
		return text;
	}
}

GUID const& Firmware::GlobalVariableVendor() {
	return EfiGlobalVariable;
}

FirmwareType Firmware::GetType() {
	FIRMWARE_TYPE type;
	if (!::GetFirmwareType(&type))
		return FirmwareType::Unknown;
	switch (type) {
		case FirmwareTypeBios: return FirmwareType::Bios;
		case FirmwareTypeUefi: return FirmwareType::Uefi;
	}
	return FirmwareType::Unknown;
}

std::optional<std::vector<UefiVariable>> Firmware::EnumVariables() {
	SecurityHelper::EnablePrivilege(SE_SYSTEM_ENVIRONMENT_NAME, true);
	ULONG size = 0;
	auto status = ::NtEnumerateSystemEnvironmentValuesEx(SystemEnvironmentValueInformation, nullptr, &size);
	std::unique_ptr<BYTE[]> buffer;
	for (int i = 0; i < 4 && (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW); i++) {
		// variables may be added between the calls
		size += 4096;
		buffer = std::make_unique<BYTE[]>(size);
		status = ::NtEnumerateSystemEnvironmentValuesEx(SystemEnvironmentValueInformation, buffer.get(), &size);
	}
	if (!NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return std::nullopt;
	}

	std::vector<UefiVariable> variables;
	if (!buffer)
		return variables;
	for (ULONG offset = 0; offset + sizeof(VARIABLE_NAME_AND_VALUE) <= size; ) {
		auto entry = reinterpret_cast<VARIABLE_NAME_AND_VALUE const*>(buffer.get() + offset);
		UefiVariable v;
		v.Name = entry->Name;
		v.Vendor = entry->VendorGuid;
		v.Attributes = entry->Attributes;
		if (entry->ValueOffset && offset + entry->ValueOffset + entry->ValueLength <= size) {
			auto value = reinterpret_cast<BYTE const*>(entry) + entry->ValueOffset;
			v.Value.assign(value, value + entry->ValueLength);
		}
		variables.push_back(std::move(v));
		if (entry->NextEntryOffset == 0)
			break;
		offset += entry->NextEntryOffset;
	}
	return variables;
}

BootConfiguration Firmware::GetBootConfiguration(std::vector<UefiVariable> const& variables) {
	BootConfiguration config;
	config.Current = GetUInt16(variables, L"BootCurrent");
	config.Next = GetUInt16(variables, L"BootNext");
	config.Timeout = GetUInt16(variables, L"Timeout");
	config.SecureBoot = GetFlag(variables, L"SecureBoot");
	config.SetupMode = GetFlag(variables, L"SetupMode");

	std::vector<uint16_t> order;
	if (auto v = FindGlobal(variables, L"BootOrder"))
		for (size_t i = 0; i + 1 < v->Value.size(); i += sizeof(uint16_t)) {
			uint16_t number;
			memcpy(&number, v->Value.data() + i, sizeof(number));
			order.push_back(number);
		}

	// Boot#### with four hex digits
	for (auto& v : variables) {
		if (!::IsEqualGUID(v.Vendor, EfiGlobalVariable) || v.Name.size() != 8 || v.Name.compare(0, 4, L"Boot") != 0
			|| !std::all_of(v.Name.begin() + 4, v.Name.end(), ::iswxdigit))
			continue;
		BootEntry entry;
		entry.Number = (uint16_t)::wcstoul(v.Name.c_str() + 4, nullptr, 16);
		if (!ParseLoadOption(v.Value, entry))
			continue;
		if (auto it = std::ranges::find(order, entry.Number); it != order.end())
			entry.Order = (int)(it - order.begin());
		config.Entries.push_back(std::move(entry));
	}
	std::ranges::sort(config.Entries, [](auto& a, auto& b) {
		// the ordered ones first
		auto key = [](BootEntry const& e) { return std::pair(e.Order < 0 ? INT_MAX : e.Order, e.Number); };
		return key(a) < key(b);
		});
	return config;
}

TpmInfo Tpm::GetInfo() {
	TpmInfo info;
	TPM_DEVICE_INFO device{};
	if (auto result = ::Tbsi_GetDeviceInfo(sizeof(device), &device); result != TBS_SUCCESS) {
		info.Error = result;
		return info;
	}
	info.Present = true;
	info.Version = device.tpmVersion;
	info.InterfaceType = device.tpmInterfaceType;
	info.ImplementationRevision = device.tpmImpRevision;
	if (device.tpmVersion != TPM_VERSION_20)
		return info;

	TBS_CONTEXT_PARAMS2 params{};
	params.version = TBS_CONTEXT_VERSION_TWO;
	params.includeTpm20 = 1;
	TBS_HCONTEXT context;
	if (auto result = ::Tbsi_Context_Create(reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&params), &context); result != TBS_SUCCESS) {
		info.Error = result;
		return info;
	}
	// TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_FAMILY_INDICATOR, 64): the fixed properties, a read-only query.
	// Big-endian: tag TPM_ST_NO_SESSIONS, size, command code, capability, first property, count
	BYTE command[] = {
		0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40,
	};
	BYTE response[1024];
	UINT32 length = sizeof(response);
	auto result = ::Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, command, sizeof(command),
		response, &length);
	::Tbsip_Context_Close(context);
	// the header (tag, size, response code), more data, the capability and the count, then property-value pairs
	if (result != TBS_SUCCESS || length < 19 || ReadUInt32(response + 6) != 0) {
		info.Error = result != TBS_SUCCESS ? result : ReadUInt32(response + 6);
		return info;
	}
	auto count = ReadUInt32(response + 15);
	std::wstring vendor[4];
	for (uint32_t i = 0; i < count && 19 + (i + 1) * 8 <= length; i++) {
		auto p = response + 19 + i * 8;
		auto property = ReadUInt32(p), value = ReadUInt32(p + 4);
		switch (property) {
			case 0x100: info.Family = FourChars(value); break;
			case 0x101: info.Level = value; break;
			case 0x102: info.Revision = value; break;
			case 0x103: info.DayOfYear = value; break;
			case 0x104: info.Year = value; break;
			case 0x105: info.Manufacturer = FourChars(value); break;
			case 0x106: case 0x107: case 0x108: case 0x109: vendor[property - 0x106] = FourChars(value); break;
			case 0x10b: info.FirmwareVersion1 = value; break;
			case 0x10c: info.FirmwareVersion2 = value; break;
		}
	}
	for (auto& part : vendor)
		info.VendorString += part;
	return info;
}
