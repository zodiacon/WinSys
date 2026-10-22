#include "pch.h"
#include "Zombies.h"
#include "Handles.h"
#include "Helpers.h"
#include <unordered_set>
#include <algorithm>
#include <wil/resource.h>

using namespace WinSys;

namespace {
	// a duplicate of a holder's handle that can tell whether the process exited, and its times
	wil::unique_handle Duplicate(HANDLE hOwner, HANDLE value) {
		wil::unique_handle h;
		// more access than the holder's handle has is checked against the process's security; its own access may do
		if (!::DuplicateHandle(hOwner, value, ::GetCurrentProcess(), h.addressof(), PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0))
			::DuplicateHandle(hOwner, value, ::GetCurrentProcess(), h.addressof(), 0, FALSE, DUPLICATE_SAME_ACCESS);
		return h;
	}

	// whether the process exited (its exit time, or its signaled state); its times when they can be read
	bool HasExited(HANDLE hProcess, int64_t& created, int64_t& exited) {
		FILETIME create{}, exit{}, kernel, user;
		if (::GetProcessTimes(hProcess, &create, &exit, &kernel, &user)) {
			created = (int64_t)ULARGE_INTEGER{ create.dwLowDateTime, create.dwHighDateTime }.QuadPart;
			exited = (int64_t)ULARGE_INTEGER{ exit.dwLowDateTime, exit.dwHighDateTime }.QuadPart;
			return exited != 0;
		}
		return ::WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0;
	}
}

std::optional<std::vector<ZombieProcess>> ZombieProcesses::Find() {
	// the system's handle table; the size needed grows between calls
	ULONG size = 1 << 22;
	std::unique_ptr<BYTE[]> buffer;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	for (int i = 0; i < 6 && status == STATUS_INFO_LENGTH_MISMATCH; i++) {
		buffer = std::make_unique<BYTE[]>(size);
		ULONG len = 0;
		status = ::NtQuerySystemInformation(SystemExtendedHandleInformation, buffer.get(), size, &len);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
			size = (std::max)(size * 2, len + (1 << 20));
	}
	if (!NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return std::nullopt;
	}

	auto table = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX const*>(buffer.get());
	auto self = (ULONG_PTR)::GetCurrentProcessId();
	std::unordered_map<USHORT, bool> isProcessType;
	std::unordered_map<ULONG_PTR, wil::unique_handle> owners;	// opened for duplicating; null if they can't be
	std::unordered_set<void*> live;	// process objects found running (their addresses are known only when elevated)
	std::unordered_map<void*, size_t> byObject;	// zombies by address
	std::vector<ZombieProcess> zombies;
	for (ULONG_PTR i = 0; i < table->NumberOfHandles; i++) {
		auto& entry = table->Handles[i];
		auto pid = (ULONG_PTR)entry.UniqueProcessId;
		if (pid == self)
			continue;
		auto [type, added] = isProcessType.try_emplace(entry.ObjectTypeIndex, false);
		if (added)
			type->second = ObjectTypes::GetName(entry.ObjectTypeIndex) == L"Process";
		if (!type->second || (entry.Object && live.contains(entry.Object)))
			continue;

		ZombieHolder holder{ (uint32_t)pid, (uint64_t)entry.HandleValue, entry.GrantedAccess };
		// another handle to a zombie already found
		if (entry.Object)
			if (auto it = byObject.find(entry.Object); it != byObject.end()) {
				zombies[it->second].Holders.push_back(holder);
				continue;
			}

		auto owner = owners.find(pid);
		if (owner == owners.end())
			owner = owners.emplace(pid, wil::unique_handle(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pid))).first;
		if (!owner->second)
			continue;
		auto hProcess = Duplicate(owner->second.get(), entry.HandleValue);
		if (!hProcess)
			continue;
		int64_t created = 0, exited = 0;
		if (!HasExited(hProcess.get(), created, exited)) {
			if (entry.Object)
				live.insert(entry.Object);
			continue;
		}

		auto zombiePid = ::GetProcessId(hProcess.get());
		// without addresses, by its ID and creation time (an ID is reused only once its process object is gone)
		if (!entry.Object) {
			auto it = std::ranges::find_if(zombies, [&](auto& z) { return z.Pid == zombiePid && z.CreateTime == created; });
			if (it != zombies.end()) {
				it->Holders.push_back(holder);
				continue;
			}
		}
		ZombieProcess zombie;
		zombie.Pid = zombiePid;
		zombie.Object = entry.Object;
		zombie.CreateTime = created;
		zombie.ExitTime = exited;
		DWORD code = 0;
		if (::GetExitCodeProcess(hProcess.get(), &code))
			zombie.ExitCode = code;
		// the NT name, which the process object keeps after the exit (QueryFullProcessImageName fails then)
		BYTE nameBuffer[sizeof(UNICODE_STRING) + MAX_PATH * 2 * sizeof(WCHAR)];
		if (NT_SUCCESS(::NtQueryInformationProcess(hProcess.get(), ProcessImageFileName, nameBuffer, sizeof(nameBuffer), nullptr))) {
			auto name = reinterpret_cast<UNICODE_STRING const*>(nameBuffer);
			std::wstring ntName(name->Buffer, name->Length / sizeof(WCHAR));
			auto dosName = Helpers::GetDosNameFromNtName(ntName.c_str());
			zombie.ImagePath = dosName.empty() ? ntName : dosName;
		}
		zombie.Holders.push_back(holder);
		if (entry.Object)
			byObject[entry.Object] = zombies.size();
		zombies.push_back(std::move(zombie));
	}
	return zombies;
}
