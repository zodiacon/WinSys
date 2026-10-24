#include "pch.h"
#include "Pipes.h"

using namespace WinSys;

namespace {
	std::optional<std::vector<PipeEntry>> EnumRoot(PCWSTR root, bool mailslot) {
		UNICODE_STRING name;
		::RtlInitUnicodeString(&name, root);
		OBJECT_ATTRIBUTES attr;
		InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		IO_STATUS_BLOCK iosb;
		HANDLE hDir;
		// not FILE_DIRECTORY_FILE: the mailslot file system's root fails it (STATUS_OBJECT_NAME_INVALID)
		auto status = ::NtOpenFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_SYNCHRONOUS_IO_NONALERT);
		if (!NT_SUCCESS(status)) {
			::SetLastError(::RtlNtStatusToDosError(status));
			return std::nullopt;
		}

		std::vector<PipeEntry> entries;
		std::vector<BYTE> buffer(1 << 16);
		for (bool first = true;; first = false) {
			status = ::NtQueryDirectoryFile(hDir, nullptr, nullptr, nullptr, &iosb, buffer.data(), (ULONG)buffer.size(),
				FileDirectoryInformation, FALSE, nullptr, first);
			if (status == STATUS_NO_MORE_FILES || (!first && status == STATUS_NO_SUCH_FILE))
				break;
			if (!NT_SUCCESS(status)) {
				if (!first)
					break;	// what was read so far
				::NtClose(hDir);
				// an empty root
				if (status == STATUS_NO_SUCH_FILE)
					return entries;
				::SetLastError(::RtlNtStatusToDosError(status));
				return std::nullopt;
			}
			for (auto p = buffer.data();;) {
				auto info = reinterpret_cast<FILE_DIRECTORY_INFORMATION const*>(p);
				PipeEntry e;
				e.Name.assign(info->FileName, info->FileNameLength / sizeof(WCHAR));
				e.Mailslot = mailslot;
				if (!mailslot) {
					e.Instances = info->EndOfFile.QuadPart;
					// unlimited (PIPE_UNLIMITED_INSTANCES) comes as 0xFFFFFFFF
					e.MaxInstances = info->AllocationSize.QuadPart;
					if (e.MaxInstances == 0xFFFFFFFF)
						e.MaxInstances = -1;
				}
				e.Created = info->CreationTime.QuadPart;
				if (!e.Name.empty())
					entries.push_back(std::move(e));
				if (info->NextEntryOffset == 0)
					break;
				p += info->NextEntryOffset;
			}
		}
		::NtClose(hDir);
		return entries;
	}
}

std::wstring PipeEntry::Win32Path() const {
	return (Mailslot ? L"\\\\.\\mailslot\\" : L"\\\\.\\pipe\\") + Name;
}

std::optional<std::vector<PipeEntry>> Pipes::EnumPipes() {
	return EnumRoot(L"\\Device\\NamedPipe\\", false);
}

std::optional<std::vector<PipeEntry>> Pipes::EnumMailslots() {
	return EnumRoot(L"\\Device\\Mailslot\\", true);
}
