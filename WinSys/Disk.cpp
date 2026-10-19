#include "pch.h"
#include <algorithm>
#include <wil/resource.h>
#include "Disk.h"

using namespace WinSys;

std::vector<DiskVolume> DiskInfo::GetVolumes() {
	std::vector<DiskVolume> volumes;
	// no "insert a disk" message boxes for empty removable drives
	DWORD oldMode;
	::SetThreadErrorMode(SEM_FAILCRITICALERRORS, &oldMode);

	auto drives = ::GetLogicalDrives();
	for (int i = 0; i < 26; i++) {
		if ((drives & (1 << i)) == 0)
			continue;

		DiskVolume volume{};
		volume.Letter = wchar_t(L'A' + i);
		volume.Root = std::wstring(1, volume.Letter) + L":\\";
		volume.DriveType = ::GetDriveType(volume.Root.c_str());
		if (volume.DriveType != DRIVE_FIXED && volume.DriveType != DRIVE_REMOVABLE)
			continue;

		// a subst drive is a folder on another drive: its target is a DOS path (\??\C:\...), not a volume device
		WCHAR device[] = L"X:", target[MAX_PATH];
		device[0] = volume.Letter;
		if (::QueryDosDevice(device, target, _countof(target)) && ::wcsncmp(target, L"\\??\\", 4) == 0)
			continue;

		WCHAR label[MAX_PATH + 1], fs[MAX_PATH + 1];
		if (!::GetVolumeInformation(volume.Root.c_str(), label, _countof(label), nullptr, nullptr, nullptr, fs, _countof(fs)))
			continue;	// no media
		volume.Label = label;
		volume.FileSystem = fs;
		Refresh(volume);
		volumes.push_back(std::move(volume));
	}
	::SetThreadErrorMode(oldMode, nullptr);
	return volumes;
}

bool DiskInfo::Refresh(DiskVolume& volume) {
	ULARGE_INTEGER total, free;
	if (::GetDiskFreeSpaceEx(volume.Root.c_str(), nullptr, &total, &free)) {
		volume.TotalBytes = total.QuadPart;
		volume.FreeBytes = free.QuadPart;
	}

	// no access needed: IOCTL_DISK_PERFORMANCE is FILE_ANY_ACCESS
	WCHAR path[] = L"\\\\.\\X:";
	path[4] = volume.Letter;
	wil::unique_hfile hVolume(::CreateFile(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
	DISK_PERFORMANCE perf;
	DWORD bytes;
	volume.HasPerformance = hVolume && ::DeviceIoControl(hVolume.get(), IOCTL_DISK_PERFORMANCE, nullptr, 0, &perf, sizeof(perf), &bytes, nullptr);
	if (!volume.HasPerformance)
		return false;

	volume.BytesRead = perf.BytesRead.QuadPart;
	volume.BytesWritten = perf.BytesWritten.QuadPart;
	volume.ReadTime = perf.ReadTime.QuadPart;
	volume.WriteTime = perf.WriteTime.QuadPart;
	volume.IdleTime = perf.IdleTime.QuadPart;
	volume.QueryTime = perf.QueryTime.QuadPart;
	volume.ReadCount = perf.ReadCount;
	volume.WriteCount = perf.WriteCount;
	volume.QueueDepth = perf.QueueDepth;
	return true;
}

void DiskTracker::Update() {
	std::vector<DiskVolume> current;
	auto drives = ::GetLogicalDrives();
	if (drives != m_Drives) {
		// drives came or went: enumerate again (this also reads the labels, which don't change otherwise)
		m_Drives = drives;
		current = DiskInfo::GetVolumes();
	}
	else {
		current.reserve(m_Volumes.size());
		for (auto& v : m_Volumes) {
			DiskVolume volume = v;
			DiskInfo::Refresh(volume);
			current.push_back(std::move(volume));
		}
	}

	std::vector<Volume> volumes;
	volumes.reserve(current.size());
	for (auto& dv : current) {
		Volume volume;
		static_cast<DiskVolume&>(volume) = std::move(dv);
		auto prev = std::find_if(m_Volumes.begin(), m_Volumes.end(), [&](auto& v) { return v.Letter == volume.Letter; });
		if (prev != m_Volumes.end() && prev->HasPerformance && volume.HasPerformance && volume.QueryTime > prev->QueryTime) {
			// the interval comes from the driver's own timestamps (100 ns units)
			double interval = double(volume.QueryTime - prev->QueryTime);
			double seconds = interval / 10000000;
			auto delta = [](uint64_t now, uint64_t before) { return now >= before ? double(now - before) : 0.0; };
			volume.ReadRate = delta(volume.BytesRead, prev->BytesRead) / seconds;
			volume.WriteRate = delta(volume.BytesWritten, prev->BytesWritten) / seconds;
			// the request counts are 32 bit and wrap; unsigned subtraction handles that
			uint32_t reads = volume.ReadCount - prev->ReadCount, writes = volume.WriteCount - prev->WriteCount;
			volume.ReadsPerSecond = reads / seconds;
			volume.WritesPerSecond = writes / seconds;
			volume.ActivePercent = std::clamp(100.0 * (1.0 - delta(volume.IdleTime, prev->IdleTime) / interval), 0.0, 100.0);
			if (reads + writes > 0)
				volume.ResponseTime = (delta(volume.ReadTime, prev->ReadTime) + delta(volume.WriteTime, prev->WriteTime)) / (reads + writes) / 10000;
		}
		volumes.push_back(std::move(volume));
	}
	m_Volumes = std::move(volumes);
}

std::vector<DiskTracker::Volume> const& DiskTracker::GetVolumes() const {
	return m_Volumes;
}
