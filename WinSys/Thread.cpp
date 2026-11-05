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

void* Thread::GetStartAddress() const noexcept {
	void* address = nullptr;
	if (!NT_SUCCESS(::NtQueryInformationThread(m_handle, ThreadQuerySetWin32StartAddress, &address, sizeof(address), nullptr)))
		return nullptr;
	return address;
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
	auto teb = GetTebAddress(m_handle);
	if (teb == 0)
		return ComFlags::Error;
	auto process = Process::OpenById(::GetProcessIdOfThread(m_handle), ProcessAccessMask::QueryLimitedInformation | ProcessAccessMask::VmRead);
	if (!process)
		return ComFlags::Error;
	return GetComFlags(process->Handle(), teb, IsWow64(process->Handle()));
}

uint64_t Thread::GetTebAddress(HANDLE hThread) noexcept {
	THREAD_BASIC_INFORMATION tbi;
	if (!NT_SUCCESS(::NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)))
		return 0;
	return (uint64_t)tbi.TebBaseAddress;
}

bool Thread::IsWow64(HANDLE hProcess) noexcept {
	// a 32-bit Windows runs 32-bit processes natively: their TEB is the only one
	static const bool is64bit = SystemInformation::GetBasicSystemInfo().MaximumAppAddress > (void*)(1LL << 32);
	BOOL wow = FALSE;
	return is64bit && ::IsWow64Process(hProcess, &wow) && wow;
}

ComFlags Thread::GetComFlags(HANDLE hProcess, uint64_t teb, bool wow64) noexcept {
	if (teb == 0)
		return ComFlags::Error;
	// COM's per-thread data (ole32's SOleTlsData) is TEB.ReservedForOle; its flags (OLETLS_*) come after the thread base
	// and the allocator pointers and the apartment ID: at 0x14 in a 64-bit process, 0xC in a 32-bit one, whose code
	// uses the 32-bit TEB, two pages after the 64-bit one in a WOW64 process (as in GetSubProcessTag)
	uint64_t ole = 0;
	if (wow64) {
		ULONG ole32 = 0;
		if (!::ReadProcessMemory(hProcess, (BYTE*)teb + 0x2000 + offsetof(TEB32, ReservedForOle), &ole32, sizeof(ole32), nullptr))
			return ComFlags::Error;
		ole = ole32;
	}
	else if (!::ReadProcessMemory(hProcess, (BYTE*)teb + offsetof(TEB, ReservedForOle), &ole, sizeof(PVOID), nullptr))
		return ComFlags::Error;
	// COM was never used on the thread
	if (ole == 0)
		return ComFlags::None;
	DWORD flags = 0;
	if (!::ReadProcessMemory(hProcess, (BYTE*)ole + (wow64 ? 0xC : 0x14), &flags, sizeof(flags), nullptr))
		return ComFlags::Error;
	return ComFlags(flags);
}

std::wstring Thread::ComApartmentText(ComFlags flags, bool processHasMta) {
	if (flags == ComFlags::Error)
		return L"";
	auto has = [&](ComFlags f) { return (flags & f) == f; };
	std::wstring text;
	if (has(ComFlags::STA))
		text = has(ComFlags::ASTA) ? L"ASTA" : L"STA";
	else if (has(ComFlags::MTA))
		text = L"MTA";
	else
		// not initialized: a thread of a process with an MTA is in it, implicitly
		return processHasMta ? L"Implicit MTA" : L"";
	if (has(ComFlags::WinRTInitialize))
		text += L" (WinRT)";
	if (has(ComFlags::InNeutralApartment))
		text += L", in the NTA";
	if (has(ComFlags::ThreadUninitializing))
		text += L", uninitializing";
	return text;
}

bool Thread::IsValid() const noexcept {
	return m_handle != nullptr;
}

ThreadPriorityLevel Thread::GetPriority() const noexcept {
	return static_cast<ThreadPriorityLevel>(::GetThreadPriority(m_handle));
}

bool Thread::SetPriority(ThreadPriorityLevel priority) noexcept {
	return ::SetThreadPriority(m_handle, static_cast<int>(priority));
}

bool Thread::GetAffinity(uint16_t& group, KAFFINITY& mask, KAFFINITY& allowed) const noexcept {
	GROUP_AFFINITY affinity{};
	if (!::GetThreadGroupAffinity(m_handle, &affinity))
		return false;
	group = affinity.Group;
	mask = affinity.Mask;
	// a process's mask is its affinity only while it's in one group (0 otherwise)
	DWORD_PTR processMask = 0, systemMask = 0;
	if (auto hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ::GetProcessIdOfThread(m_handle))) {
		::GetProcessAffinityMask(hProcess, &processMask, &systemMask);
		::CloseHandle(hProcess);
	}
	auto count = ::GetActiveProcessorCount(group);
	KAFFINITY active = count >= sizeof(KAFFINITY) * 8 ? ~KAFFINITY(0) : (KAFFINITY(1) << count) - 1;
	allowed = processMask ? (KAFFINITY)processMask & active : active;
	return true;
}

bool Thread::SetAffinity(KAFFINITY mask) noexcept {
	GROUP_AFFINITY affinity{};
	if (!::GetThreadGroupAffinity(m_handle, &affinity))
		return false;
	affinity.Mask = mask;
	return ::SetThreadGroupAffinity(m_handle, &affinity, nullptr);
}

bool Thread::SetGroupAffinity(uint16_t group, KAFFINITY mask) noexcept {
	GROUP_AFFINITY affinity{ mask, group };
	return ::SetThreadGroupAffinity(m_handle, &affinity, nullptr);
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
