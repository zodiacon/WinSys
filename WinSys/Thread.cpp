#include "pch.h"
#include "Thread.h"
#include "SystemInformation.h"
#include "subprocesstag.h"
#include "Processes.h"

using namespace WinSys;

Thread::Thread(HANDLE handle, bool own) : m_handle(handle), m_own(own) {}

bool Thread::Open(uint32_t tid, ThreadAccessMask accessMask) noexcept {
	auto hThread = ::OpenThread(static_cast<ACCESS_MASK>(accessMask), FALSE, tid);
	if (!hThread)
		return false;

	if (m_own && m_handle)
		::CloseHandle(m_handle);
	m_handle = hThread;
	m_own = true;
	return true;
}

Thread::~Thread() noexcept {
	if (m_own && m_handle)
		::CloseHandle(m_handle);
}

int Thread::GetMemoryPriority() const noexcept {
	int priority = -1;
	ULONG len;
	::NtQueryInformationThread(m_handle, ThreadPagePriority, &priority, sizeof(priority), &len);
	return priority;
}

IoPriority Thread::GetIoPriority() const noexcept {
	auto priority = IoPriority::Unknown;
	ULONG len;
	::NtQueryInformationThread(m_handle, ThreadIoPriority, &priority, sizeof(priority), &len);
	return priority;
}

uint64_t Thread::GetCycleTime() const noexcept {
	ULONG64 cycles = 0;
	::QueryThreadCycleTime(m_handle, &cycles);
	return cycles;
}

size_t Thread::GetSubProcessTag() const noexcept {
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
	if (!is64bit || process->IsWow64Process()) {
		// a WOW64 thread's 32-bit code (the service host's) tags its 32-bit TEB, which WOW64 puts two pages after the
		// 64-bit one that ThreadBasicInformation gives (as in Process::GetStructures)
		auto teb = (TEB32*)((BYTE*)tbi.TebBaseAddress + (is64bit ? 0x2000 : 0));
		::ReadProcessMemory(process->Handle(), (BYTE*)teb + offsetof(TEB32, SubProcessTag), &tag, sizeof(ULONG), nullptr);
	}
	else {
		auto teb = (TEB*)tbi.TebBaseAddress;
		::ReadProcessMemory(process->Handle(), (BYTE*)teb + offsetof(TEB, SubProcessTag), &tag, sizeof(tag), nullptr);
	}
	return tag;
}

std::wstring Thread::GetServiceNameByTag(uint32_t pid) const noexcept {
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
	if (err || info.OutParams.pszName == nullptr)
		return L"";
	// allocated for the caller
	std::wstring name(info.OutParams.pszName);
	::LocalFree(info.OutParams.pszName);
	return name;
}

ComFlags Thread::GetComFlags() const noexcept {
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

bool Thread::IsValid() const noexcept {
	return m_handle != nullptr;
}

ThreadPriorityLevel Thread::GetPriority() const noexcept {
	return static_cast<ThreadPriorityLevel>(::GetThreadPriority(m_handle));
}

CpuNumber Thread::GetIdealProcessor() const noexcept {
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

bool Thread::Terminate(uint32_t exitCode) noexcept {
	return ::TerminateThread(m_handle, exitCode);
}

bool Thread::Suspend() noexcept {
	return ::SuspendThread(m_handle) != (DWORD)-1;
}

bool Thread::Resume() noexcept {
	return ::ResumeThread(m_handle) != (DWORD)-1;
}

int64_t Thread::GetCreateTime() const noexcept {
	FILETIME created, exited, kernel, user;
	if (!::GetThreadTimes(m_handle, &created, &exited, &kernel, &user))
		return 0;
	return (int64_t)ULARGE_INTEGER{ created.dwLowDateTime, created.dwHighDateTime }.QuadPart;
}
