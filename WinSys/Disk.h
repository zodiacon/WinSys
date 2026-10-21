#pragma once

#include <string>
#include <vector>
#include <cstdint>

//
// Drive (volume with a drive letter) capacity and I/O statistics. The counters come from IOCTL_DISK_PERFORMANCE on the
// volume, which needs no elevation (FILE_ANY_ACCESS); the volume handle is opened for each query and not kept,
// so removable drives can still be ejected.
//

namespace WinSys {
	struct DiskVolume {
		wchar_t Letter;	// 'C'
		std::wstring Root;	// "C:\"
		std::wstring Label, FileSystem;
		uint32_t DriveType;	// DRIVE_FIXED, DRIVE_REMOVABLE
		uint64_t TotalBytes, FreeBytes;	// free to all users, not just the caller's quota

		bool HasPerformance;	// the counters below are valid
		uint64_t BytesRead, BytesWritten;
		uint64_t ReadTime, WriteTime, IdleTime;	// 100 ns units
		uint64_t QueryTime;	// timestamp of the counters, 100 ns units
		uint32_t ReadCount, WriteCount;
		uint32_t QueueDepth;	// requests outstanding now
	};

	struct DiskInfo final {
		// Fixed and removable drives with a drive letter. Drives with no media (an empty card reader) and subst drives are skipped.
		[[nodiscard]] static std::vector<DiskVolume> GetVolumes();
		// Refreshes the counters of a volume returned by GetVolumes, and its free space if space is true
		static bool Refresh(DiskVolume& volume, bool space = true);
	};

	//
	// Tracks the drives and computes rates on each Update(). Drives that appear (a USB drive plugged in) or disappear
	// are picked up by the next update, media inserted in an empty removable drive within 5 seconds. A drive's rates
	// are 0 on the update it first appears in.
	//
	class DiskTracker {
	public:
		struct Volume : DiskVolume {
			double ReadRate{ 0 }, WriteRate{ 0 };	// bytes per second
			double ReadsPerSecond{ 0 }, WritesPerSecond{ 0 };
			double ActivePercent{ 0 };	// time the volume was busy with I/O
			double ResponseTime{ 0 };	// average time per completed request in the interval, milliseconds
		};

		void Update();

		[[nodiscard]] std::vector<Volume> const& GetVolumes() const;

	private:
		std::vector<Volume> m_Volumes;	// in drive letter order
		uint32_t m_Drives{ 0 };	// GetLogicalDrives() at the last full enumeration
		uint64_t m_SpaceTime{ 0 };	// GetTickCount64() when the free space was last read (it changes slowly)

		[[nodiscard]] bool HasNewMedia(uint32_t drives) const;
	};
}
