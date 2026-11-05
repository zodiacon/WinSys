#include "pch.h"
#include "KernelCallbacks.h"
#include "KernelModules.h"
#include "ServiceManager.h"
#include "PEFile.h"
#include <fltUser.h>
#include <algorithm>
#include <wil/resource.h>

#pragma comment(lib, "fltlib")

using namespace WinSys;

namespace {
	struct Registration {
		PCSTR Function;
		CallbackKind Kind;
		PCWSTR Description;
		bool Numbered{ false };	// a version number follows: FwpsCalloutRegister0..3
	};

	const Registration Registrations[] = {
		{ "PsSetCreateProcessNotifyRoutine", CallbackKind::Process, L"Process creation and exit" },
		{ "PsSetCreateProcessNotifyRoutineEx", CallbackKind::Process, L"Process creation (can deny it) and exit" },
		{ "PsSetCreateProcessNotifyRoutineEx2", CallbackKind::Process, L"Process creation (can deny it) and exit, Pico processes too" },
		{ "PsSetCreateThreadNotifyRoutine", CallbackKind::Thread, L"Thread creation and exit" },
		{ "PsSetCreateThreadNotifyRoutineEx", CallbackKind::Thread, L"Thread creation (on the new thread) and exit" },
		{ "PsSetLoadImageNotifyRoutine", CallbackKind::ImageLoad, L"Image mapping: executables, DLLs, drivers" },
		{ "PsSetLoadImageNotifyRoutineEx", CallbackKind::ImageLoad, L"Image mapping: executables, DLLs, drivers" },
		{ "CmRegisterCallback", CallbackKind::Registry, L"Registry operations (can deny or change them)" },
		{ "CmRegisterCallbackEx", CallbackKind::Registry, L"Registry operations at an altitude (can deny or change them)" },
		{ "ObRegisterCallbacks", CallbackKind::Object, L"Handle opens and duplications of processes, threads and desktops (can strip access)" },
		{ "FltRegisterFilter", CallbackKind::FileSystem, L"A file system minifilter" },
		{ "IoRegisterFsRegistrationChange", CallbackKind::FileSystem, L"File systems' registration: a legacy file system filter" },
		{ "IoRegisterFsRegistrationChangeEx", CallbackKind::FileSystem, L"File systems' registration: a legacy file system filter" },
		{ "IoRegisterFsRegistrationChangeMountAware", CallbackKind::FileSystem, L"File systems' registration and mounts: a legacy file system filter" },
		{ "FwpsCalloutRegister", CallbackKind::Network, L"A Windows Filtering Platform callout: network traffic", true },
		{ "NdisFRegisterFilterDriver", CallbackKind::Network, L"An NDIS filter driver: network packets" },
		{ "IoRegisterBootDriverCallback", CallbackKind::BootDriver, L"Boot-start drivers' initialization (Early Launch Antimalware)" },
		{ "KeRegisterBugCheckCallback", CallbackKind::BugCheck, L"A bug check (crash)" },
		{ "KeRegisterBugCheckReasonCallback", CallbackKind::BugCheck, L"A bug check: data for the crash dump" },
		{ "IoRegisterShutdownNotification", CallbackKind::Shutdown, L"System shutdown" },
		{ "IoRegisterLastChanceShutdownNotification", CallbackKind::Shutdown, L"System shutdown, after the file systems flushed" },
		{ "PoRegisterPowerSettingCallback", CallbackKind::Power, L"A power setting's changes" },
		{ "ExRegisterCallback", CallbackKind::CallbackObject, L"An executive callback object (\\Callback\\PowerState, \\Callback\\SetSystemTime...)" },
		{ "IoRegisterPlugPlayNotification", CallbackKind::PlugAndPlay, L"Device arrival and removal, device interfaces' changes" },
		{ "IoRegisterContainerNotification", CallbackKind::Session, L"User sessions' changes (logon, logoff, connections)" },
		{ "KeRegisterNmiCallback", CallbackKind::Nmi, L"Non-maskable interrupts" },
		{ "DbgSetDebugPrintCallback", CallbackKind::DebugPrint, L"The kernel's debug print output" },
		{ "SeRegisterLogonSessionTerminatedRoutine", CallbackKind::LogonSession, L"Logon sessions' termination" },
		{ "SeRegisterLogonSessionTerminatedRoutineEx", CallbackKind::LogonSession, L"Logon sessions' termination" },
	};

	Registration const* Find(std::string_view function) {
		for (auto& r : Registrations) {
			std::string_view name(r.Function);
			if (!r.Numbered && function == name)
				return &r;
			if (r.Numbered && function.size() > name.size() && function.starts_with(name)
				&& std::all_of(function.begin() + name.size(), function.end(), [](char c) { return c >= '0' && c <= '9'; }))
				return &r;
		}
		return nullptr;
	}

	std::wstring StringAt(void const* base, USHORT offset, USHORT length) {
		return std::wstring((PCWSTR)((BYTE const*)base + offset), length / sizeof(WCHAR));
	}

	void ReadInstances(Minifilter& filter) {
		std::vector<BYTE> buffer(1 << 14);
		DWORD returned = 0;
		HANDLE hFind = nullptr;
		auto hr = ::FilterInstanceFindFirst(filter.Name.c_str(), InstanceAggregateStandardInformation, buffer.data(), (DWORD)buffer.size(), &returned, &hFind);
		if (FAILED(hr))
			return;
		for (;;) {
			auto info = (INSTANCE_AGGREGATE_STANDARD_INFORMATION const*)buffer.data();
			MinifilterInstance instance;
			if (info->Flags & FLTFL_IASI_IS_MINIFILTER) {
				auto& m = info->Type.MiniFilter;
				instance.Name = StringAt(info, m.InstanceNameBufferOffset, m.InstanceNameLength);
				instance.Altitude = StringAt(info, m.AltitudeBufferOffset, m.AltitudeLength);
				instance.Volume = StringAt(info, m.VolumeNameBufferOffset, m.VolumeNameLength);
				instance.FileSystem = (uint32_t)m.VolumeFileSystemType;
				instance.FrameId = m.FrameID;
				instance.Detached = (m.Flags & FLTFL_IASIM_DETACHED_VOLUME) != 0;
			}
			else {
				auto& l = info->Type.LegacyFilter;
				instance.Legacy = true;
				instance.Altitude = StringAt(info, l.AltitudeBufferOffset, l.AltitudeLength);
				instance.Volume = StringAt(info, l.VolumeNameBufferOffset, l.VolumeNameLength);
			}
			if (!instance.Volume.empty()) {
				WCHAR dos[MAX_PATH];
				if (SUCCEEDED(::FilterGetDosName(instance.Volume.c_str(), dos, _countof(dos))))
					instance.DosVolume = dos;
			}
			filter.Instances.push_back(std::move(instance));
			hr = ::FilterInstanceFindNext(hFind, InstanceAggregateStandardInformation, buffer.data(), (DWORD)buffer.size(), &returned);
			if (FAILED(hr))
				break;
		}
		::FilterInstanceFindClose(hFind);
	}
}

std::optional<std::vector<Minifilter>> KernelCallbacks::EnumMinifilters() {
	std::vector<BYTE> buffer(1 << 12);
	DWORD returned = 0;
	HANDLE hFind = nullptr;
	auto hr = ::FilterFindFirst(FilterAggregateStandardInformation, buffer.data(), (DWORD)buffer.size(), &returned, &hFind);
	if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
		return std::vector<Minifilter>();
	if (FAILED(hr)) {
		::SetLastError(HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : hr);
		return {};
	}
	std::vector<Minifilter> filters;
	for (;;) {
		auto info = (FILTER_AGGREGATE_STANDARD_INFORMATION const*)buffer.data();
		Minifilter filter;
		if (info->Flags & FLTFL_ASI_IS_MINIFILTER) {
			auto& m = info->Type.MiniFilter;
			filter.Name = StringAt(info, m.FilterNameBufferOffset, m.FilterNameLength);
			filter.Altitude = StringAt(info, m.FilterAltitudeBufferOffset, m.FilterAltitudeLength);
			filter.FrameId = m.FrameID;
			filter.InstanceCount = m.NumberOfInstances;
		}
		else {
			auto& l = info->Type.LegacyFilter;
			filter.Legacy = true;
			filter.Name = StringAt(info, l.FilterNameBufferOffset, l.FilterNameLength);
			filter.Altitude = StringAt(info, l.FilterAltitudeBufferOffset, l.FilterAltitudeLength);
		}
		filters.push_back(std::move(filter));
		hr = ::FilterFindNext(hFind, FilterAggregateStandardInformation, buffer.data(), (DWORD)buffer.size(), &returned);
		if (FAILED(hr))
			break;
	}
	::FilterFindClose(hFind);

	for (auto& f : filters) {
		if (!f.Legacy)
			ReadInstances(f);
		if (auto config = ServiceManager::GetServiceConfiguration(f.Name))
			f.ImagePath = KernelModules::DriverImagePath(f.Name, config->BinaryPathName);
	}
	// altitudes are decimal numbers, some with a fraction ("385201.5"): highest first
	std::ranges::stable_sort(filters, [](auto& a, auto& b) { return ::wcstod(a.Altitude.c_str(), nullptr) > ::wcstod(b.Altitude.c_str(), nullptr); });
	return filters;
}

CallbackDrivers KernelCallbacks::EnumCallbackDrivers() {
	CallbackDrivers result;
	for (auto& m : KernelModules::Enum()) {
		result.Modules++;
		auto pe = PEFile::Load(m.Path);
		if (!pe) {
			result.Unreadable.push_back(m.Path);
			continue;
		}
		CallbackDriver driver;
		for (auto& library : pe->GetImports())
			for (auto& f : library.Functions) {
				auto r = f.Name.empty() ? nullptr : Find(f.Name);
				if (!r)
					continue;
				driver.Imports.push_back({ f.Name, library.Name, r->Kind });
				driver.Kinds |= r->Kind;
			}
		if (driver.Imports.empty())
			continue;
		driver.Name = m.Name;
		driver.Path = m.Path;
		driver.LoadOrder = m.LoadOrder;
		result.Drivers.push_back(std::move(driver));
	}
	return result;
}

CallbackKind KernelCallbacks::KindOf(std::string_view function) {
	auto r = Find(function);
	return r ? r->Kind : CallbackKind::None;
}

PCWSTR KernelCallbacks::Describe(std::string_view function) {
	auto r = Find(function);
	return r ? r->Description : L"";
}

std::wstring KernelCallbacks::KindsText(CallbackKind kinds) {
	static const PCWSTR names[] = { L"Process", L"Thread", L"Image Load", L"Registry", L"Object", L"File System", L"Network",
		L"Boot Driver", L"Bug Check", L"Shutdown", L"Power", L"Callback Object", L"Plug and Play", L"Session", L"NMI",
		L"Debug Print", L"Logon Session" };
	std::wstring text;
	for (int i = 0; i < _countof(names); i++)
		if ((uint32_t)kinds & (1u << i)) {
			if (!text.empty())
				text += L", ";
			text += names[i];
		}
	return text;
}

PCWSTR KernelCallbacks::FileSystemName(uint32_t type) {
	switch ((FLT_FILESYSTEM_TYPE)type) {
		case FLT_FSTYPE_RAW: return L"RAW";
		case FLT_FSTYPE_NTFS: return L"NTFS";
		case FLT_FSTYPE_FAT: return L"FAT";
		case FLT_FSTYPE_CDFS: return L"CDFS";
		case FLT_FSTYPE_UDFS: return L"UDF";
		case FLT_FSTYPE_LANMAN: return L"SMB";
		case FLT_FSTYPE_WEBDAV: return L"WebDAV";
		case FLT_FSTYPE_RDPDR: return L"RDP";
		case FLT_FSTYPE_NFS: return L"NFS";
		case FLT_FSTYPE_MUP: return L"Mup";
		case FLT_FSTYPE_FS_REC: return L"Recognizer";
		case FLT_FSTYPE_EXFAT: return L"exFAT";
		case FLT_FSTYPE_NPFS: return L"Named Pipes";
		case FLT_FSTYPE_MSFS: return L"Mailslots";
		case FLT_FSTYPE_CSVFS: return L"CSVFS";
		case FLT_FSTYPE_REFS: return L"ReFS";
		case FLT_FSTYPE_CIMFS: return L"CimFS";
		case FLT_FSTYPE_UNKNOWN: return L"Unknown";
	}
	return L"Other";
}
