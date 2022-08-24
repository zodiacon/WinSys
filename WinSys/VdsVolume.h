#pragma once

#include <string>

namespace WinSys::Vds {
	enum class VdsHealth {
		Unknown = 0,
		Healthy = 1,
		Rebuilding = 2,
		Stale = 3,
		Failing = 4,
		FailingRedundancy = 5,
		FailedRedundancy = 6,
		FailedRedundancyFailing = 7,
		Failed = 8,
		Replaced = 9,
		PendingFailure = 10,
		Degraded = 11
	};

	enum class VdsVolumeType {
		Unknown = 0,
		Simple = 10,
		Span = 11,
		Stripe = 12,
		Mirror = 13,
		Parity = 14
	};

	enum class VdsVolumeStatus {
		Unknown = 0,
		Online = 1,
		NoMedia = 3,
		Failed = 5,
		Offline = 4
	};

	enum class VdsTransitionState {
		Unknown = 0,
		Stable = 1,
		Extending = 2,
		Shrinking = 3,
		Reconfiging = 4,
		Restriping = 5
	};

	enum class VdsFileSystemType {
		Unknown = 0,
		RAW,
		FAT,
		FAT32,
		NTFS,
		CDFS,
		UDF,
		EXFAT,
		CSVFS,
		REFS
	};

	struct VdsVolumeProperties {
		GUID Id;
		VdsVolumeType Type;
		VdsVolumeStatus Status;
		VdsHealth Health;
		VdsTransitionState TransitionState;
		uint64_t Size;
		uint32_t Flags;
		VdsFileSystemType RecommendedFileSystemType;
		std::wstring Name;
	};
}
