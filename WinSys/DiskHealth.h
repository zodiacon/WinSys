#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

//
// A physical disk's health, as the drive reports it: an NVMe drive's SMART / Health Information log page, an ATA
// drive's SMART attributes (IOCTL_STORAGE_PREDICT_FAILURE's vendor data, with the drive's failure prediction) and the
// temperature Windows reads from it. Every query goes through IOCTL_STORAGE_QUERY_PROPERTY or another FILE_ANY_ACCESS
// control code on a handle opened with no access, so none needs elevation. USB bridges mostly pass none of this on.
//

namespace WinSys {
	enum class DiskHealthState {
		Unknown,	// the drive reports nothing (a USB stick)
		Good,
		Warning,	// worn, errors recorded, running hot
		Critical,	// the drive warns itself (NVMe critical warning, SMART failure predicted)
	};

	enum class DiskHealthSource { None, Nvme, Ata };

	struct SmartAttribute {
		uint8_t Id;
		uint8_t Current, Worst;	// normalized values (higher is better, mostly)
		uint64_t Raw;			// 6 bytes, little endian; vendors pack more than one value in some
	};

	struct DiskHealth {
		uint32_t DiskNumber{ 0 };
		std::wstring Model;		// vendor and product ("Samsung SSD 9100 PRO 4TB")
		std::wstring BusType;	// "NVMe", "SATA", "USB"...
		DiskHealthSource Source{ DiskHealthSource::None };
		DiskHealthState State{ DiskHealthState::Unknown };
		std::vector<std::wstring> Problems;	// why it isn't Good ("2 media errors", "SMART predicts a failure")

		std::optional<int> Temperature;			// Celsius
		std::optional<int> TemperatureWarning;	// the drive's warning threshold (NVMe WCTEMP, the temperature property's)
		std::optional<int> TemperatureCritical;	// NVMe CCTEMP
		std::optional<uint64_t> PowerOnHours, PowerCycles;

		// NVMe
		uint8_t CriticalWarning{ 0 };			// NVME_HEALTH_INFO_LOG's bits
		std::optional<uint32_t> PercentageUsed;	// of the rated endurance; may pass 100
		std::optional<uint32_t> AvailableSpare, AvailableSpareThreshold;	// percent
		std::optional<uint64_t> BytesRead, BytesWritten;	// data units (512,000 bytes) converted
		std::optional<uint64_t> UnsafeShutdowns, MediaErrors, ErrorLogEntries;

		// ATA
		bool PredictFailure{ false };
		std::optional<uint64_t> StartStopCount, ReallocatedSectors, PendingSectors, UncorrectableSectors, ReportedUncorrectable;
		std::vector<SmartAttribute> Attributes;
	};

	struct DiskHealthReader final {
		// the disk's health, read now; nothing if the disk can't be opened (the last error set). A disk that reports
		// nothing is returned with Source None and State Unknown (its model and bus type only)
		[[nodiscard]] static std::optional<DiskHealth> Read(uint32_t diskNumber);
		// whether the disk is spinning (GetDevicePowerState): a sleeping hard disk would be woken by the SMART query;
		// true if it can't be told (an SSD always is)
		[[nodiscard]] static bool IsPoweredOn(uint32_t diskNumber);
		// the physical disks a drive letter's volume lies on (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS; more than one for a
		// spanned or mirrored volume); empty if it can't be read
		[[nodiscard]] static std::vector<uint32_t> GetVolumeDisks(wchar_t letter);

		// parsing, apart for the tests: NVME_HEALTH_INFO_LOG (512 bytes), NVME_IDENTIFY_CONTROLLER_DATA's temperature
		// thresholds (WCTEMP at 266, CCTEMP at 268, Kelvin), the ATA SMART attribute table (512 bytes: a version word,
		// then 30 entries of 12 bytes), then the verdict from what was read
		static bool ParseNvmeHealthLog(void const* log, size_t size, DiskHealth& health);
		static bool ParseNvmeIdentifyController(void const* data, size_t size, DiskHealth& health);
		static bool ParseAtaSmart(void const* data, size_t size, bool predictFailure, DiskHealth& health);
		static void Evaluate(DiskHealth& health);

		[[nodiscard]] static wchar_t const* StateText(DiskHealthState state);
	};
}
