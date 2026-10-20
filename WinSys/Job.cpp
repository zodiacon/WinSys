#include "pch.h"
#include "Job.h"
#include "Handles.h"
#include <algorithm>
#include <unordered_set>

using namespace WinSys;

std::wstring JobInfo::GetName(HANDLE hJob) {
	BYTE buffer[1024];
	ULONG len;
	if (!NT_SUCCESS(::NtQueryObject(hJob, ObjectNameInformation, buffer, sizeof(buffer), &len)))
		return L"";
	auto name = reinterpret_cast<UNICODE_STRING const*>(buffer);
	return std::wstring(name->Buffer, name->Length / sizeof(WCHAR));
}

uint32_t JobInfo::GetActiveProcesses(HANDLE hJob) {
	JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
	return ::QueryInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectBasicAccountingInformation, &info, sizeof(info), nullptr)
		? info.ActiveProcesses : 0;
}

std::vector<uint32_t> JobInfo::GetProcessIds(HANDLE hJob) {
	DWORD count = 64;
	for (int i = 0; i < 4; i++) {
		auto size = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + count * sizeof(ULONG_PTR);
		auto buffer = std::make_unique<BYTE[]>(size);
		auto list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buffer.get());
		if (::QueryInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectBasicProcessIdList, list, (DWORD)size, nullptr)) {
			std::vector<uint32_t> ids;
			for (DWORD n = 0; n < list->NumberOfProcessIdsInList; n++)
				ids.push_back((uint32_t)list->ProcessIdList[n]);
			return ids;
		}
		if (::GetLastError() != ERROR_MORE_DATA)
			break;
		// processes are added between the calls
		count = list->NumberOfAssignedProcesses + 64;
	}
	return {};
}

std::optional<std::vector<ProcessJob>> JobInfo::FindProcessJobs(HANDLE hProcess, bool* ordered) {
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
	std::unordered_map<USHORT, bool> isJobType;
	std::unordered_map<ULONG_PTR, wil::unique_handle> owners;	// opened for duplicating; null if they can't be
	std::unordered_set<void*> seen;	// job objects already checked (their addresses are known only when elevated)
	std::vector<ProcessJob> jobs;
	auto self = ::GetCurrentProcess();
	for (ULONG_PTR i = 0; i < table->NumberOfHandles; i++) {
		auto& entry = table->Handles[i];
		auto [type, added] = isJobType.try_emplace(entry.ObjectTypeIndex, false);
		if (added)
			type->second = ObjectTypes::GetName(entry.ObjectTypeIndex) == L"Job";
		if (!type->second || (entry.Object && seen.contains(entry.Object)))
			continue;

		auto pid = (ULONG_PTR)entry.UniqueProcessId;
		auto owner = owners.find(pid);
		if (owner == owners.end())
			owner = owners.emplace(pid, wil::unique_handle(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pid))).first;
		if (!owner->second)
			continue;
		wil::unique_handle hJob;
		if (!::DuplicateHandle(owner->second.get(), entry.HandleValue, self, hJob.addressof(), JOB_OBJECT_QUERY, FALSE, 0))
			continue;
		if (entry.Object)
			seen.insert(entry.Object);

		BOOL inJob = FALSE;
		if (!::IsProcessInJob(hProcess, hJob.get(), &inJob) || !inJob)
			continue;
		// another handle to a job already found (when the addresses aren't known)
		if (std::ranges::any_of(jobs, [&](auto& job) { return ::NtCompareObjects(job.Handle.get(), hJob.get()) == STATUS_SUCCESS; }))
			continue;
		ProcessJob job;
		job.Name = GetName(hJob.get());
		SILOOBJECT_BASIC_INFORMATION silo;
		job.Silo = NT_SUCCESS(::NtQueryInformationJobObject(hJob.get(), (JOBOBJECTINFOCLASS)JobObjectSiloBasicInformation,
			&silo, sizeof(silo), nullptr));
		job.ActiveProcesses = GetActiveProcesses(hJob.get());
		job.Handle = std::move(hJob);
		jobs.push_back(std::move(job));
	}

	// innermost first: an ancestor holds its children's processes and more
	std::ranges::stable_sort(jobs, {}, &ProcessJob::ActiveProcesses);
	if (ordered)
		*ordered = std::ranges::adjacent_find(jobs, {}, &ProcessJob::ActiveProcesses) == jobs.end();
	return jobs;
}
