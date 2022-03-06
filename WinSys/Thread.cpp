#include "pch.h"
#include "Thread.h"
#include "SystemInformation.h"
#include "subprocesstag.h"
#include "Processes.h"

using namespace WinSys;

Thread::Thread(HANDLE handle, bool own) : m_handle(handle), m_own(own) {}

bool Thread::Open(uint32_t tid, ThreadAccessMask accessMask) {
	auto hThread = ::OpenThread(static_cast<ACCESS_MASK>(accessMask), FALSE, tid);
	if (!hThread)
		return false;

	if (m_own && m_handle)
		::CloseHandle(m_handle);
	m_handle = hThread;
	m_own = true;
	return true;
}

Thread::~Thread() {
	if (m_own && m_handle)
		::CloseHandle(m_handle);
}

int Thread::GetMemoryPriority() const {
	int priority = -1;
	ULONG len;
	::NtQueryInformationThread(m_handle, ThreadPagePriority, &priority, sizeof(priority), &len);
	return priority;
}

IoPriority Thread::GetIoPriority() const {
	auto priority = IoPriority::Unknown;
	ULONG len;
	::NtQueryInformationThread(m_handle, ThreadIoPriority, &priority, sizeof(priority), &len);
	return priority;
}

size_t Thread::GetSubProcessTag() const {
	THREAD_BASIC_INFORMATION tbi;
	auto status = ::NtQueryInformationThread(m_handle, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
	if (!NT_SUCCESS(status))
		return 0;

	if (tbi.TebBaseAddress == 0)
		return 0;

	bool is64bit = SystemInformation::GetBasicSystemInfo().MaximumAppAddress > (void*)(1LL << 32);
	auto pid = ::GetProcessIdOfThread(m_handle);
	auto process = Process::OpenById(pid, ProcessAccessMask::QueryLimitedInformation | ProcessAccessMask::VmRead);
	if (!process)
		return 0;

	size_t tag = 0;
	if (!is64bit || (process->IsWow64Process() && is64bit)) {
		auto teb = (TEB32*)tbi.TebBaseAddress;
		::ReadProcessMemory(process->Handle(), (BYTE*)teb + offsetof(TEB32, SubProcessTag), &tag, sizeof(ULONG), nullptr);
	}
	else {
		auto teb = (TEB*)tbi.TebBaseAddress;
		::ReadProcessMemory(process->Handle(), (BYTE*)teb + offsetof(TEB, SubProcessTag), &tag, sizeof(tag), nullptr);
	}
	return tag;
}

std::wstring Thread::GetServiceNameByTag(uint32_t pid) const {
	static auto QueryTagInformation = (PQUERY_TAG_INFORMATION)::GetProcAddress(::GetModuleHandle(L"advapi32"), "I_QueryTagInformation");
	if (QueryTagInformation == nullptr)
		return L"";
	auto tag = GetSubProcessTag();
	if (tag == 0)
		return L"";
	TAG_INFO_NAME_FROM_TAG info = { 0 };
	info.InParams.dwPid = pid;
	info.InParams.dwTag = static_cast<uint32_t>(tag);
	auto err = QueryTagInformation(nullptr, eTagInfoLevelNameFromTag, &info);
	if (err)
		return L"";
	return info.OutParams.pszName;
}

ComFlags Thread::GetComFlags() const {
	THREAD_BASIC_INFORMATION tbi;
	auto status = ::NtQueryInformationThread(m_handle, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
	if (!NT_SUCCESS(status))
		return ComFlags::Error;

	if (tbi.TebBaseAddress == 0)
		return ComFlags::Error;

	bool is64bit = SystemInformation::GetBasicSystemInfo().MaximumAppAddress > (void*)(1LL << 32);
	auto pid = ::GetProcessIdOfThread(m_handle);
	auto process = Process::OpenById(pid, ProcessAccessMask::QueryLimitedInformation | ProcessAccessMask::VmRead);
	if (!process)
		return ComFlags::Error;

	void* ole = nullptr;
	bool wow = false;
	auto teb = tbi.TebBaseAddress;
	if (!is64bit || process->IsWow64Process()) {
		wow = true;
		auto offset = offsetof(TEB32, ReservedForOle);
		::ReadProcessMemory(process->Handle(), (BYTE*)teb + offset, &ole, sizeof(ULONG), nullptr);
	}
	else {
		::ReadProcessMemory(process->Handle(), (BYTE*)teb + offsetof(TEB, ReservedForOle), &ole, sizeof(ole), nullptr);
	}
	if(ole == nullptr)
		return ComFlags::None;

	BYTE buffer[32];
	if(!::ReadProcessMemory(process->Handle(), ole, buffer, sizeof(buffer), nullptr))
		return ComFlags::Error;

	auto flags = wow ? (buffer + 12) : (buffer + 20);
	return ComFlags(*(DWORD*)flags);
}

bool Thread::IsValid() const {
	return m_handle != nullptr;
}

ThreadPriorityLevel Thread::GetPriority() const {
	return static_cast<ThreadPriorityLevel>(::GetThreadPriority(m_handle));
}

CpuNumber Thread::GetIdealProcessor() const {
	PROCESSOR_NUMBER cpu;
	ULONG len;
	CpuNumber number;
	if (NT_SUCCESS(::NtQueryInformationThread(m_handle, ThreadIdealProcessorEx, &cpu, sizeof(cpu), &len))) {
		number.Group = cpu.Group;
		number.Number = cpu.Number;
	}
	else {
		number.Number = -1;
		number.Group = -1;
	}
	return number;
}

std::unique_ptr<Thread> Thread::OpenById(uint32_t tid, ThreadAccessMask accessMask) {
	HANDLE hThread = ::OpenThread(static_cast<ACCESS_MASK>(accessMask), FALSE, tid);
	if (!hThread)
		return nullptr;

	return std::make_unique<Thread>(hThread, true);
}
