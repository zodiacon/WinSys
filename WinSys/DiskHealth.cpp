#include "pch.h"
#include "DiskHealth.h"
#include <nvme.h>
#include <wil/resource.h>

using namespace WinSys;

namespace {
	static_assert(sizeof(NVME_HEALTH_INFO_LOG) == 512);
	static_assert(FIELD_OFFSET(NVME_IDENTIFY_CONTROLLER_DATA, WCTEMP) == 266);
	static_assert(FIELD_OFFSET(NVME_IDENTIFY_CONTROLLER_DATA, CCTEMP) == 268);

	wil::unique_hfile OpenDisk(uint32_t diskNumber) {
		// no access: the queries below are FILE_ANY_ACCESS, so no elevation is needed
		auto name = L"\\\\.\\PhysicalDrive" + std::to_wstring(diskNumber);
		return wil::unique_hfile(::CreateFileW(name.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
	}

	// a 16-byte NVMe counter's low 64 bits (more would take centuries to reach)
	uint64_t Counter(UCHAR const* value) {
		uint64_t result;
		memcpy(&result, value, sizeof(result));
		return result;
	}

	// Kelvin to Celsius; nothing for 0 (not reported)
	std::optional<int> Celsius(unsigned kelvin) {
		return kelvin ? std::optional<int>((int)kelvin - 273) : std::nullopt;
	}

	PCWSTR BusTypeName(STORAGE_BUS_TYPE type) {
		switch (type) {
			case BusTypeScsi: return L"SCSI";
			case BusTypeAtapi: return L"ATAPI";
			case BusTypeAta: return L"ATA";
			case BusType1394: return L"1394";
			case BusTypeSsa: return L"SSA";
			case BusTypeFibre: return L"Fibre Channel";
			case BusTypeUsb: return L"USB";
			case BusTypeRAID: return L"RAID";
			case BusTypeiScsi: return L"iSCSI";
			case BusTypeSas: return L"SAS";
			case BusTypeSata: return L"SATA";
			case BusTypeSd: return L"SD";
			case BusTypeMmc: return L"MMC";
			case BusTypeVirtual: return L"Virtual";
			case BusTypeFileBackedVirtual: return L"Virtual (file)";
			case BusTypeSpaces: return L"Storage Spaces";
			case BusTypeNvme: return L"NVMe";
			case BusTypeSCM: return L"SCM";
			case BusTypeUfs: return L"UFS";
		}
		return L"";
	}

	std::wstring Trimmed(char const* text) {
		std::string s(text);
		auto first = s.find_first_not_of(' ');
		auto last = s.find_last_not_of(' ');
		if (first == std::string::npos)
			return {};
		s = s.substr(first, last - first + 1);
		return std::wstring(s.begin(), s.end());	// ASCII, as the descriptors are
	}

	// the model and bus type (STORAGE_DEVICE_DESCRIPTOR); the bus type, or BusTypeUnknown
	STORAGE_BUS_TYPE ReadDescriptor(HANDLE hDisk, DiskHealth& health) {
		STORAGE_PROPERTY_QUERY query{ StorageDeviceProperty, PropertyStandardQuery };
		BYTE buffer[1024]{};
		DWORD bytes;
		if (!::DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer, sizeof(buffer) - 1, &bytes, nullptr)
			|| bytes < sizeof(STORAGE_DEVICE_DESCRIPTOR))
			return BusTypeUnknown;
		auto desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR const*>(buffer);
		auto text = [&](DWORD offset) { return offset && offset < bytes ? Trimmed(reinterpret_cast<char const*>(buffer + offset)) : std::wstring(); };
		auto vendor = text(desc->VendorIdOffset), product = text(desc->ProductIdOffset);
		// NVMe and SATA drives mostly have the vendor in the product already
		health.Model = vendor.empty() || product.starts_with(vendor) ? product : vendor + L" " + product;
		health.BusType = BusTypeName(desc->BusType);
		return desc->BusType;
	}

	// an NVMe query through StorageDeviceProtocolSpecificProperty (or the adapter's): a log page or identify data
	bool QueryNvme(HANDLE hDisk, STORAGE_PROPERTY_ID property, STORAGE_PROTOCOL_NVME_DATA_TYPE type, ULONG value, ULONG subValue,
		std::vector<BYTE>& data, DWORD length) {
		auto headerSize = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
		std::vector<BYTE> buffer(headerSize + length);
		auto query = reinterpret_cast<STORAGE_PROPERTY_QUERY*>(buffer.data());
		query->PropertyId = property;
		query->QueryType = PropertyStandardQuery;
		auto protocol = reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(query->AdditionalParameters);
		protocol->ProtocolType = ProtocolTypeNvme;
		protocol->DataType = type;
		protocol->ProtocolDataRequestValue = value;
		protocol->ProtocolDataRequestSubValue = subValue;
		protocol->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
		protocol->ProtocolDataLength = length;
		DWORD bytes;
		if (!::DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, buffer.data(), (DWORD)buffer.size(), buffer.data(), (DWORD)buffer.size(), &bytes, nullptr))
			return false;
		// the answer: a STORAGE_PROTOCOL_DATA_DESCRIPTOR, whose data offset counts from its ProtocolSpecificData
		auto desc = reinterpret_cast<STORAGE_PROTOCOL_DATA_DESCRIPTOR const*>(buffer.data());
		auto& answer = desc->ProtocolSpecificData;
		auto start = FIELD_OFFSET(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData) + answer.ProtocolDataOffset;
		if (answer.ProtocolDataOffset < sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) || answer.ProtocolDataLength < length || start + length > bytes)
			return false;
		data.assign(buffer.begin() + start, buffer.begin() + start + length);
		return true;
	}

	// the temperature Windows reads from the drive (StorageDeviceTemperatureProperty: ATA's SCT or SMART, SCSI's log
	// page); NVMe drives answer the health log instead, here
	void ReadTemperatureProperty(HANDLE hDisk, DiskHealth& health) {
		STORAGE_PROPERTY_QUERY query{ StorageDeviceTemperatureProperty, PropertyStandardQuery };
		BYTE buffer[1024]{};
		DWORD bytes;
		if (!::DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer, sizeof(buffer), &bytes, nullptr)
			|| bytes < sizeof(STORAGE_TEMPERATURE_DATA_DESCRIPTOR))
			return;
		auto desc = reinterpret_cast<STORAGE_TEMPERATURE_DATA_DESCRIPTOR const*>(buffer);
		if (desc->InfoCount == 0 || bytes < FIELD_OFFSET(STORAGE_TEMPERATURE_DATA_DESCRIPTOR, TemperatureInfo) + sizeof(STORAGE_TEMPERATURE_INFO))
			return;
		auto& info = desc->TemperatureInfo[0];
		// SHORT_MIN: not reported
		if (info.Temperature != SHRT_MIN && !health.Temperature)
			health.Temperature = info.Temperature;
		if (info.OverThreshold != SHRT_MIN && info.OverThreshold > 0 && !health.TemperatureWarning)
			health.TemperatureWarning = info.OverThreshold;
		if (desc->CriticalTemperature != SHRT_MIN && desc->CriticalTemperature > 0 && !health.TemperatureCritical)
			health.TemperatureCritical = desc->CriticalTemperature;
	}

	std::wstring Count(uint64_t count, PCWSTR one, PCWSTR many) {
		return std::to_wstring(count) + L" " + (count == 1 ? one : many);
	}
}

bool DiskHealthReader::ParseNvmeHealthLog(void const* data, size_t size, DiskHealth& health) {
	if (!data || size < sizeof(NVME_HEALTH_INFO_LOG))
		return false;
	auto log = static_cast<NVME_HEALTH_INFO_LOG const*>(data);
	health.Source = DiskHealthSource::Nvme;
	health.CriticalWarning = log->CriticalWarning.AsUchar;
	health.Temperature = Celsius(log->Temperature[0] | (log->Temperature[1] << 8));
	health.AvailableSpare = log->AvailableSpare;
	health.AvailableSpareThreshold = log->AvailableSpareThreshold;
	health.PercentageUsed = log->PercentageUsed;
	// thousands of 512-byte units, rounded up
	health.BytesRead = Counter(log->DataUnitRead) * 512000;
	health.BytesWritten = Counter(log->DataUnitWritten) * 512000;
	health.PowerCycles = Counter(log->PowerCycle);
	health.PowerOnHours = Counter(log->PowerOnHours);
	health.UnsafeShutdowns = Counter(log->UnsafeShutdowns);
	health.MediaErrors = Counter(log->MediaErrors);
	health.ErrorLogEntries = Counter(log->ErrorInfoLogEntryCount);
	return true;
}

bool DiskHealthReader::ParseNvmeIdentifyController(void const* data, size_t size, DiskHealth& health) {
	if (!data || size < sizeof(NVME_IDENTIFY_CONTROLLER_DATA))
		return false;
	auto id = static_cast<NVME_IDENTIFY_CONTROLLER_DATA const*>(data);
	if (auto warning = Celsius(id->WCTEMP))
		health.TemperatureWarning = warning;
	if (auto critical = Celsius(id->CCTEMP))
		health.TemperatureCritical = critical;
	return true;
}

bool DiskHealthReader::ParseAtaSmart(void const* data, size_t size, bool predictFailure, DiskHealth& health) {
	if (!data || size < 2 + 30 * 12)
		return false;
	auto bytes = static_cast<uint8_t const*>(data);
	health.Attributes.clear();
	for (int i = 0; i < 30; i++) {
		auto entry = bytes + 2 + i * 12;
		if (entry[0] == 0)
			continue;
		SmartAttribute a{ entry[0], entry[3], entry[4], 0 };
		for (int b = 5; b >= 0; b--)
			a.Raw = a.Raw << 8 | entry[5 + b];
		health.Attributes.push_back(a);
	}
	if (health.Attributes.empty() && !predictFailure)
		return false;
	health.Source = DiskHealthSource::Ata;
	health.PredictFailure = predictFailure;
	// counts in the low 32 bits: vendors pack more in the upper bytes (Seagate's power-on hours, the temperatures' range)
	auto low = [&](uint8_t id) -> std::optional<uint64_t> {
		auto it = std::ranges::find(health.Attributes, id, &SmartAttribute::Id);
		return it == health.Attributes.end() ? std::nullopt : std::optional<uint64_t>(it->Raw & 0xFFFFFFFF);
	};
	health.StartStopCount = low(4);
	health.ReallocatedSectors = low(5);
	health.PowerOnHours = low(9);
	health.PowerCycles = low(12);
	health.ReportedUncorrectable = low(187);
	health.PendingSectors = low(197);
	health.UncorrectableSectors = low(198);
	// the temperature's lowest byte (194, else the airflow's 190); the temperature property is preferred when there is one
	for (uint8_t id : { (uint8_t)194, (uint8_t)190 })
		if (auto it = std::ranges::find(health.Attributes, id, &SmartAttribute::Id); it != health.Attributes.end() && (it->Raw & 0xFF) > 0) {
			health.Temperature = (int)(it->Raw & 0xFF);
			break;
		}
	return true;
}

void DiskHealthReader::Evaluate(DiskHealth& health) {
	health.Problems.clear();
	if (health.Source == DiskHealthSource::None) {
		health.State = DiskHealthState::Unknown;
		return;
	}
	bool critical = false, warning = false;
	auto problem = [&](bool isCritical, std::wstring text) {
		(isCritical ? critical : warning) = true;
		health.Problems.push_back(std::move(text));
	};
	if (health.Source == DiskHealthSource::Nvme) {
		// the drive's own critical warnings (NVMe 1.4's bits)
		auto bits = health.CriticalWarning;
		if (bits & 0x01)
			problem(true, L"spare capacity below its threshold");
		if (bits & 0x02)
			problem(true, L"temperature beyond its limits");
		if (bits & 0x04)
			problem(true, L"reliability degraded by media errors");
		if (bits & 0x08)
			problem(true, L"media read-only");
		if (bits & 0x10)
			problem(true, L"volatile memory backup failed");
		if (bits & 0x20)
			problem(true, L"persistent memory region read-only");
		if (health.PercentageUsed && *health.PercentageUsed >= 90)
			problem(false, std::to_wstring(*health.PercentageUsed) + L"% of its rated endurance used");
		if (health.MediaErrors && *health.MediaErrors > 0)
			problem(false, Count(*health.MediaErrors, L"media error", L"media errors"));
	}
	else {
		if (health.PredictFailure)
			problem(true, L"SMART predicts a failure");
		if (health.ReallocatedSectors && *health.ReallocatedSectors > 0)
			problem(false, Count(*health.ReallocatedSectors, L"reallocated sector", L"reallocated sectors"));
		if (health.PendingSectors && *health.PendingSectors > 0)
			problem(false, Count(*health.PendingSectors, L"sector pending reallocation", L"sectors pending reallocation"));
		if (health.UncorrectableSectors && *health.UncorrectableSectors > 0)
			problem(false, Count(*health.UncorrectableSectors, L"uncorrectable sector", L"uncorrectable sectors"));
		if (health.ReportedUncorrectable && *health.ReportedUncorrectable > 0)
			problem(false, Count(*health.ReportedUncorrectable, L"uncorrectable error", L"uncorrectable errors"));
	}
	if (health.Temperature && health.TemperatureWarning && *health.Temperature >= *health.TemperatureWarning && !(health.CriticalWarning & 0x02))
		problem(false, L"running hot (" + std::to_wstring(*health.Temperature) + L" \u00B0C, warning at " + std::to_wstring(*health.TemperatureWarning) + L" \u00B0C)");
	health.State = critical ? DiskHealthState::Critical : warning ? DiskHealthState::Warning : DiskHealthState::Good;
}

std::optional<DiskHealth> DiskHealthReader::Read(uint32_t diskNumber) {
	auto hDisk = OpenDisk(diskNumber);
	if (!hDisk)
		return std::nullopt;
	DiskHealth health;
	health.DiskNumber = diskNumber;
	auto bus = ReadDescriptor(hDisk.get(), health);
	// the model and bus type only, for a bus whose health isn't asked for
	health.NotRead = WhyNotRead(bus);
	if (!health.NotRead.empty()) {
		Evaluate(health);
		return health;
	}

	std::vector<BYTE> data;
	// NVMe: the health log for the whole controller (namespace FFFFFFFF), the thresholds from Identify Controller
	// (refused by some drivers through the device: the adapter's then)
	if (bus == BusTypeNvme
		&& QueryNvme(hDisk.get(), StorageDeviceProtocolSpecificProperty, NVMeDataTypeLogPage, NVME_LOG_PAGE_HEALTH_INFO, 0, data, sizeof(NVME_HEALTH_INFO_LOG)))
		ParseNvmeHealthLog(data.data(), data.size(), health);
	if (health.Source == DiskHealthSource::Nvme
		&& (QueryNvme(hDisk.get(), StorageDeviceProtocolSpecificProperty, NVMeDataTypeIdentify, NVME_IDENTIFY_CNS_CONTROLLER, 0, data, sizeof(NVME_IDENTIFY_CONTROLLER_DATA))
			|| QueryNvme(hDisk.get(), StorageAdapterProtocolSpecificProperty, NVMeDataTypeIdentify, NVME_IDENTIFY_CNS_CONTROLLER, 0, data, sizeof(NVME_IDENTIFY_CONTROLLER_DATA))))
		ParseNvmeIdentifyController(data.data(), data.size(), health);

	// ATA: the SMART attributes with the drive's prediction (the storage stack reads them; SCSI and USB drives mostly
	// refuse)
	if (health.Source == DiskHealthSource::None) {
		STORAGE_PREDICT_FAILURE predict{};
		DWORD bytes;
		if (::DeviceIoControl(hDisk.get(), IOCTL_STORAGE_PREDICT_FAILURE, nullptr, 0, &predict, sizeof(predict), &bytes, nullptr))
			ParseAtaSmart(predict.VendorSpecific, sizeof(predict.VendorSpecific), predict.PredictFailure != 0, health);
	}
	// the drive's temperature as Windows reads it (better than SMART's raw byte, with its threshold)
	if (health.Source != DiskHealthSource::Nvme) {
		auto smart = health.Temperature;
		health.Temperature.reset();
		ReadTemperatureProperty(hDisk.get(), health);
		if (!health.Temperature)
			health.Temperature = smart;
	}
	Evaluate(health);
	return health;
}

std::wstring DiskHealthReader::WhyNotRead(uint32_t busType) {
	switch (busType) {
		case BusTypeNvme:
		case BusTypeAta:
		case BusTypeSata:
			return {};
		case BusTypeRAID:
			return L"behind a RAID controller";
		case BusTypeUnknown:
			return L"on an unknown bus";
	}
	auto name = BusTypeName((STORAGE_BUS_TYPE)busType);
	return *name ? std::wstring(L"on a ") + name + L" bus" : std::wstring(L"on an unknown bus");
}

bool DiskHealthReader::IsPoweredOn(uint32_t diskNumber) {
	auto hDisk = OpenDisk(diskNumber);
	BOOL on = TRUE;
	if (!hDisk || !::GetDevicePowerState(hDisk.get(), &on))
		return true;
	return on != FALSE;
}

std::vector<uint32_t> DiskHealthReader::GetVolumeDisks(wchar_t letter) {
	std::vector<uint32_t> disks;
	std::wstring name = L"\\\\.\\";
	name += letter;
	name += L':';
	wil::unique_hfile hVolume(::CreateFileW(name.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
	if (!hVolume)
		return disks;
	BYTE buffer[sizeof(VOLUME_DISK_EXTENTS) + 31 * sizeof(DISK_EXTENT)]{};
	DWORD bytes;
	if (!::DeviceIoControl(hVolume.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, buffer, sizeof(buffer), &bytes, nullptr))
		return disks;
	auto extents = reinterpret_cast<VOLUME_DISK_EXTENTS const*>(buffer);
	for (DWORD i = 0; i < extents->NumberOfDiskExtents && i < 32; i++)
		if (std::ranges::find(disks, extents->Extents[i].DiskNumber) == disks.end())
			disks.push_back(extents->Extents[i].DiskNumber);
	return disks;
}

wchar_t const* DiskHealthReader::StateText(DiskHealthState state) {
	switch (state) {
		case DiskHealthState::Good: return L"Good";
		case DiskHealthState::Warning: return L"Warning";
		case DiskHealthState::Critical: return L"Critical";
	}
	return L"Unknown";
}
