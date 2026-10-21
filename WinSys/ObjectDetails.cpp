#include "pch.h"
#include <wil/resource.h>
#include "ObjectDetails.h"
#include "Token.h"
#include "Job.h"

using namespace WinSys;

namespace {
	// the query that blocks for a synchronous file with I/O in progress: on a thread of its own, which the caller abandons
	// after its timeout. The thread keeps the state (and the duplicate) alive until its queries return
	struct FileQuery {
		wil::unique_handle Handle;
		FileDetails Result;
		wil::unique_event Done{ wil::EventOptions::ManualReset };

		void Run() {
			IO_STATUS_BLOCK ioStatus;
			FILE_FS_DEVICE_INFORMATION device;
			if (NT_SUCCESS(::NtQueryVolumeInformationFile(Handle.get(), &ioStatus, &device, sizeof(device), FileFsDeviceInformation))) {
				Result.DeviceType = device.DeviceType;
				Result.DeviceCharacteristics = device.Characteristics;
			}
			FILE_MODE_INFORMATION mode;
			if (NT_SUCCESS(::NtQueryInformationFile(Handle.get(), &ioStatus, &mode, sizeof(mode), FileModeInformation)))
				Result.Mode = mode.Mode;
			FILE_STANDARD_INFORMATION standard;
			if (NT_SUCCESS(::NtQueryInformationFile(Handle.get(), &ioStatus, &standard, sizeof(standard), FileStandardInformation))) {
				Result.Size = standard.EndOfFile.QuadPart;
				Result.Allocation = standard.AllocationSize.QuadPart;
				Result.Directory = standard.Directory;
				Result.DeletePending = standard.DeletePending;
				Result.Links = standard.NumberOfLinks;
			}
			FILE_POSITION_INFORMATION position;
			if (NT_SUCCESS(::NtQueryInformationFile(Handle.get(), &ioStatus, &position, sizeof(position), FilePositionInformation)))
				Result.Position = position.CurrentByteOffset.QuadPart;
			if (Result.DeviceType == FILE_DEVICE_NAMED_PIPE) {
				FILE_PIPE_LOCAL_INFORMATION pipe;
				if (NT_SUCCESS(::NtQueryInformationFile(Handle.get(), &ioStatus, &pipe, sizeof(pipe), FilePipeLocalInformation)))
					Result.Pipe = PipeDetails{ pipe.NamedPipeType, pipe.NamedPipeConfiguration, pipe.MaximumInstances, pipe.CurrentInstances,
						pipe.InboundQuota, pipe.ReadDataAvailable, pipe.OutboundQuota, pipe.WriteQuotaAvailable, pipe.NamedPipeState,
						pipe.NamedPipeEnd };
			}
			Done.SetEvent();
		}

		static DWORD WINAPI ThreadProc(void* param) {
			std::unique_ptr<std::shared_ptr<FileQuery>> self(static_cast<std::shared_ptr<FileQuery>*>(param));
			(*self)->Run();
			return 0;
		}
	};

	FileDetails QueryFile(HANDLE hFile, uint32_t timeoutMs) {
		auto query = std::make_shared<FileQuery>();
		FileDetails timedOut;
		timedOut.TimedOut = true;
		if (!::DuplicateHandle(::GetCurrentProcess(), hFile, ::GetCurrentProcess(), query->Handle.addressof(), 0, FALSE, DUPLICATE_SAME_ACCESS))
			return timedOut;
		auto param = new std::shared_ptr<FileQuery>(query);
		wil::unique_handle hThread(::CreateThread(nullptr, 64 << 10, FileQuery::ThreadProc, param, 0, nullptr));
		if (!hThread) {
			delete param;
			return timedOut;
		}
		if (::WaitForSingleObject(query->Done.get(), timeoutMs) != WAIT_OBJECT_0)
			return timedOut;	// the thread goes on with its own reference
		return query->Result;
	}

	// a copy of a handle in another process with the access a query needs, if its access allows it
	wil::unique_handle DuplicateWith(HANDLE hProcess, HANDLE source, DWORD access) {
		wil::unique_handle h;
		::DuplicateHandle(hProcess, source, ::GetCurrentProcess(), h.addressof(), access, FALSE, 0);
		return h;
	}

	int64_t ToInt64(FILETIME const& ft) {
		return (int64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime;
	}

	void QueryTypeDetails(ObjectDetails& details, HANDLE h, HANDLE hProcess, HANDLE source, uint32_t fileTimeoutMs) {
		auto& type = details.TypeName;
		if (type == L"Event") {
			EVENT_BASIC_INFORMATION info;
			if (NT_SUCCESS(::NtQueryEvent(h, EventBasicInformation, &info, sizeof(info), nullptr)))
				details.Event = EventDetails{ info.EventType == NotificationEvent, info.EventState != 0 };
		}
		else if (type == L"Mutant") {
			MUTANT_BASIC_INFORMATION info;
			if (NT_SUCCESS(::NtQueryMutant(h, MutantBasicInformation, &info, sizeof(info), nullptr))) {
				MutantDetails mutant{ info.CurrentCount, info.AbandonedState != 0 };
				MUTANT_OWNER_INFORMATION owner;
				if (info.CurrentCount <= 0 && NT_SUCCESS(::NtQueryMutant(h, MutantOwnerInformation, &owner, sizeof(owner), nullptr))) {
					mutant.OwnerProcessId = HandleToULong(owner.ClientId.UniqueProcess);
					mutant.OwnerThreadId = HandleToULong(owner.ClientId.UniqueThread);
				}
				details.Mutant = mutant;
			}
		}
		else if (type == L"Semaphore") {
			SEMAPHORE_BASIC_INFORMATION info;
			if (NT_SUCCESS(::NtQuerySemaphore(h, SemaphoreBasicInformation, &info, sizeof(info), nullptr)))
				details.Semaphore = SemaphoreDetails{ info.CurrentCount, info.MaximumCount };
		}
		else if (type == L"Timer") {
			TIMER_BASIC_INFORMATION info;
			if (NT_SUCCESS(::NtQueryTimer(h, TimerBasicInformation, &info, sizeof(info), nullptr)))
				details.Timer = TimerDetails{ info.TimerState != 0, info.RemainingTime.QuadPart };
		}
		else if (type == L"IoCompletion") {
			IO_COMPLETION_BASIC_INFORMATION info;
			if (NT_SUCCESS(::NtQueryIoCompletion(h, IoCompletionBasicInformation, &info, sizeof(info), nullptr)))
				details.IoCompletion = IoCompletionDetails{ info.Depth };
		}
		else if (type == L"Section") {
			SECTION_BASIC_INFORMATION info;
			if (NT_SUCCESS(::NtQuerySection(h, SectionBasicInformation, &info, sizeof(info), nullptr))) {
				SectionDetails section{ (uint64_t)info.MaximumSize.QuadPart, info.AllocationAttributes };
				SECTION_IMAGE_INFORMATION image;
				if ((info.AllocationAttributes & SEC_IMAGE)
					&& NT_SUCCESS(::NtQuerySection(h, SectionImageInformation, &image, sizeof(image), nullptr))) {
					section.Image = true;
					section.EntryPoint = (uint64_t)image.TransferAddress;
					section.Machine = image.Machine;
					section.Subsystem = (uint16_t)image.SubSystemType;
					section.ImageFileSize = image.ImageFileSize;
				}
				details.Section = section;
			}
		}
		else if (type == L"File")
			details.File = QueryFile(h, fileTimeoutMs);
		else if (type == L"Key") {
			// the class name follows the fixed part, which a buffer overflow still fills
			BYTE buffer[1024];
			ULONG len;
			KeyDetails key;
			if (auto status = ::NtQueryKey(h, KeyFullInformation, buffer, sizeof(buffer), &len); NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
				auto info = reinterpret_cast<KEY_FULL_INFORMATION const*>(buffer);
				key.LastWriteTime = info->LastWriteTime.QuadPart;
				key.SubKeys = info->SubKeys;
				key.Values = info->Values;
				details.Key = key;
			}
			else if (auto status = ::NtQueryKey(h, KeyBasicInformation, buffer, sizeof(buffer), &len);
				NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
				key.LastWriteTime = reinterpret_cast<KEY_BASIC_INFORMATION const*>(buffer)->LastWriteTime.QuadPart;
				details.Key = key;
			}
		}
		else if (type == L"SymbolicLink") {
			WCHAR buffer[1024];
			UNICODE_STRING target{ 0, sizeof(buffer), buffer };
			if (NT_SUCCESS(::NtQuerySymbolicLinkObject(h, &target, nullptr)))
				details.SymbolicLink = SymbolicLinkDetails{ std::wstring(target.Buffer, target.Length / sizeof(WCHAR)) };
		}
		else if (type == L"Process") {
			// queried with the access that needs, which the handle's own may not have
			auto hp = DuplicateWith(hProcess, source, PROCESS_QUERY_LIMITED_INFORMATION);
			auto target = hp ? hp.get() : h;
			if (auto pid = ::GetProcessId(target)) {
				ProcessDetails process{ pid };
				WCHAR path[MAX_PATH];
				DWORD size = _countof(path);
				if (::QueryFullProcessImageName(target, 0, path, &size))
					process.ImagePath = path;
				FILETIME create, exit, kernel, user;
				if (::GetProcessTimes(target, &create, &exit, &kernel, &user))
					process.CreateTime = ToInt64(create);
				PROCESS_BASIC_INFORMATION info;
				if (NT_SUCCESS(::NtQueryInformationProcess(target, ProcessBasicInformation, &info, sizeof(info), nullptr))
					&& info.ExitStatus != STATUS_PENDING)
					process.ExitCode = (uint32_t)info.ExitStatus;
				details.Process = std::move(process);
			}
		}
		else if (type == L"Thread") {
			auto ht = DuplicateWith(hProcess, source, THREAD_QUERY_LIMITED_INFORMATION);
			auto target = ht ? ht.get() : h;
			if (auto tid = ::GetThreadId(target)) {
				ThreadDetails thread{ tid, ::GetProcessIdOfThread(target) };
				FILETIME create, exit, kernel, user;
				if (::GetThreadTimes(target, &create, &exit, &kernel, &user))
					thread.CreateTime = ToInt64(create);
				THREAD_BASIC_INFORMATION info;
				if (NT_SUCCESS(::NtQueryInformationThread(target, ThreadBasicInformation, &info, sizeof(info), nullptr))
					&& info.ExitStatus != STATUS_PENDING)
					thread.ExitCode = (uint32_t)info.ExitStatus;
				details.Thread = thread;
			}
		}
		else if (type == L"Token") {
			// Token owns its handle: another copy
			HANDLE copy;
			if (::DuplicateHandle(::GetCurrentProcess(), h, ::GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
				WinSys::Token token(copy);
				auto [user, sid] = token.GetUserNameAndSid();
				if (sid) {
					TokenDetails info;
					info.User = user;
					info.UserSid = sid.AsString();
					auto stats = token.GetStats();
					info.LogonSession = stats.AuthenticationId;
					info.Primary = stats.TokenType == TokenPrimary;
					info.ImpersonationLevel = stats.ImpersonationLevel;
					info.SessionId = token.GetSessionId();
					info.Integrity = token.GetIntegrityLevel();
					info.Elevated = token.IsElevated();
					details.Token = std::move(info);
				}
			}
		}
		else if (type == L"Job") {
			JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
			if (::QueryInformationJobObject(h, (JOBOBJECTINFOCLASS)JobObjectBasicAccountingInformation, &info, sizeof(info), nullptr))
				details.Job = JobDetails{ JobInfo::GetName(h), info.ActiveProcesses, info.TotalProcesses, info.TotalTerminatedProcesses };
		}
	}
}

std::optional<ObjectDetails> ObjectInspector::QueryHandle(HANDLE hProcess, uint64_t value, std::wstring const& type, uint32_t fileTimeoutMs) {
	auto source = (HANDLE)(ULONG_PTR)value;
	wil::unique_handle h;
	if (!::DuplicateHandle(hProcess, source, ::GetCurrentProcess(), h.addressof(), 0, FALSE, DUPLICATE_SAME_ACCESS))
		return std::nullopt;

	// the counts first, while the duplicate holds all its references: since Windows 8.1, a handle takes 32,768 references
	// in advance (on 64-bit), and each use of it consumes one (before, a handle held one)
	ObjectDetails details;
	OBJECT_BASIC_INFORMATION basic;
	bool counts = NT_SUCCESS(::NtQueryObject(h.get(), ObjectBasicInformation, &basic, sizeof(basic), nullptr));

	// the value may have been closed and reused since it was listed: the type tells
	auto stats = QueryTypeStatistics(h.get(), &details.TypeName);
	if (!stats || details.TypeName != type) {
		::SetLastError(ERROR_INVALID_HANDLE);
		return std::nullopt;
	}
	details.TypeStatistics = *stats;

	if (counts) {
		details.GrantedAccess = basic.GrantedAccess;
		details.Attributes = basic.Attributes;
		// without the duplicate's handle and references
		auto handleReferences = ::IsWindows8Point1OrGreater() && sizeof(void*) == 8 ? 0x8000u : 1u;
		details.Handles = basic.HandleCount ? basic.HandleCount - 1 : 0;
		details.References = basic.PointerCount >= handleReferences ? basic.PointerCount - handleReferences : 0;
		details.PagedPoolCharge = basic.PagedPoolCharge;
		details.NonPagedPoolCharge = basic.NonPagedPoolCharge;
		details.CreationTime = basic.CreationTime.QuadPart;
	}

	QueryTypeDetails(details, h.get(), hProcess, source, fileTimeoutMs);
	return details;
}

std::optional<ObjectTypeStatistics> ObjectInspector::QueryTypeStatistics(HANDLE h, std::wstring* typeName) {
	BYTE buffer[2048];
	if (!NT_SUCCESS(::NtQueryObject(h, ObjectTypeInformation, buffer, sizeof(buffer), nullptr)))
		return std::nullopt;
	auto& info = *reinterpret_cast<OBJECT_TYPE_INFORMATION const*>(buffer);
	if (typeName)
		typeName->assign(info.TypeName.Buffer, info.TypeName.Length / sizeof(WCHAR));
	ObjectTypeStatistics stats;
	stats.Objects = info.TotalNumberOfObjects;
	stats.Handles = info.TotalNumberOfHandles;
	stats.PeakObjects = info.HighWaterNumberOfObjects;
	stats.PeakHandles = info.HighWaterNumberOfHandles;
	stats.ValidAccessMask = info.ValidAccessMask;
	stats.GenericMapping = info.GenericMapping;
	stats.PoolType = info.PoolType;
	stats.SecurityRequired = info.SecurityRequired;
	return stats;
}

HANDLE ObjectInspector::OpenHandle(HANDLE hProcess, uint64_t value, std::wstring const& type) {
	wil::unique_handle h;
	if (!::DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)value, ::GetCurrentProcess(), h.addressof(), 0, FALSE, DUPLICATE_SAME_ACCESS))
		return nullptr;
	BYTE buffer[1024];
	if (!NT_SUCCESS(::NtQueryObject(h.get(), ObjectTypeInformation, buffer, sizeof(buffer), nullptr))
		|| type != std::wstring_view(reinterpret_cast<OBJECT_TYPE_INFORMATION const*>(buffer)->TypeName.Buffer,
			reinterpret_cast<OBJECT_TYPE_INFORMATION const*>(buffer)->TypeName.Length / sizeof(WCHAR))) {
		::SetLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	return h.release();
}

std::vector<BYTE> ObjectInspector::GetSecurity(HANDLE h, SECURITY_INFORMATION info) {
	std::vector<BYTE> sd(1024);
	for (;;) {
		ULONG needed = 0;
		auto status = ::NtQuerySecurityObject(h, info, (PSECURITY_DESCRIPTOR)sd.data(), (ULONG)sd.size(), &needed);
		if (NT_SUCCESS(status))
			return sd;
		if (status != STATUS_BUFFER_TOO_SMALL || needed <= sd.size()) {
			::SetLastError(::RtlNtStatusToDosError(status));
			return {};
		}
		sd.resize(needed);
	}
}

bool ObjectInspector::SetSecurity(HANDLE h, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd) {
	auto status = ::NtSetSecurityObject(h, info, sd);
	if (!NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

PCWSTR ObjectInspector::DeviceTypeToString(uint32_t type) {
	switch (type) {
		case FILE_DEVICE_CD_ROM: return L"CD-ROM";
		case FILE_DEVICE_CD_ROM_FILE_SYSTEM: return L"CD-ROM File System";
		case FILE_DEVICE_DFS: return L"DFS";
		case FILE_DEVICE_DISK: return L"Disk";
		case FILE_DEVICE_DISK_FILE_SYSTEM: return L"Disk File System";
		case FILE_DEVICE_FILE_SYSTEM: return L"File System";
		case FILE_DEVICE_KEYBOARD: return L"Keyboard";
		case FILE_DEVICE_MAILSLOT: return L"Mailslot";
		case FILE_DEVICE_MOUSE: return L"Mouse";
		case FILE_DEVICE_MULTI_UNC_PROVIDER: return L"Multi UNC Provider";
		case FILE_DEVICE_NAMED_PIPE: return L"Named Pipe";
		case FILE_DEVICE_NETWORK: return L"Network";
		case FILE_DEVICE_NETWORK_FILE_SYSTEM: return L"Network File System";
		case FILE_DEVICE_NULL: return L"Null";
		case FILE_DEVICE_PRINTER: return L"Printer";
		case FILE_DEVICE_SERIAL_PORT: return L"Serial Port";
		case FILE_DEVICE_SCREEN: return L"Screen";
		case FILE_DEVICE_SOUND: return L"Sound";
		case FILE_DEVICE_TRANSPORT: return L"Transport";
		case FILE_DEVICE_UNKNOWN: return L"Unknown";
		case FILE_DEVICE_VIDEO: return L"Video";
		case FILE_DEVICE_VIRTUAL_DISK: return L"Virtual Disk";
		case FILE_DEVICE_NETWORK_REDIRECTOR: return L"Network Redirector";
		case FILE_DEVICE_BATTERY: return L"Battery";
		case FILE_DEVICE_BUS_EXTENDER: return L"Bus Extender";
		case FILE_DEVICE_MASS_STORAGE: return L"Mass Storage";
		case FILE_DEVICE_KS: return L"Kernel Streaming";
		case FILE_DEVICE_ACPI: return L"ACPI";
		case FILE_DEVICE_DVD: return L"DVD";
		case FILE_DEVICE_KSEC: return L"Security (KSecDD)";
		case FILE_DEVICE_CONSOLE: return L"Console";
		case FILE_DEVICE_TERMSRV: return L"Terminal Server";
		case FILE_DEVICE_INFINIBAND: return L"InfiniBand";
	}
	return L"";
}
