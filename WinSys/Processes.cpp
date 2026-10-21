#include "pch.h"
#include "SecurityHelper.h"
#include <TlHelp32.h>
#include <algorithm>
#include "Thread.h"
#include "Processes.h"
#include "SystemInformation.h"

using namespace WinSys;

static bool GetProcessPeb(HANDLE hProcess, PPEB peb) {
	PROCESS_BASIC_INFORMATION info;
	if (!NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &info, sizeof(info), nullptr)))
		return false;

	return ::ReadProcessMemory(hProcess, info.PebBaseAddress, peb, sizeof(*peb), nullptr);
}

static bool GetExtendedInfo(HANDLE hProcess, PROCESS_EXTENDED_BASIC_INFORMATION* info) {
	ULONG len;
	info->Size = sizeof(*info);
	auto status = ::NtQueryInformationProcess(hProcess, ProcessBasicInformation, info, sizeof(*info), &len);
	return NT_SUCCESS(status);
}

uint32_t Process::GetId() const noexcept {
	return ::GetProcessId(m_Handle.get());
}

std::wstring Process::GetName() const {
	auto name = GetFullImageName();
	auto slash = name.rfind(L'\\');
	return slash == std::wstring::npos ? name : name.substr(slash + 1);
}

std::optional<ProcessWindowInfo> Process::GetWindowInformation() const {
	auto buffer = std::make_unique<BYTE[]>(1024);
	std::optional<ProcessWindowInfo> info;
	ULONG len;
	if (!NT_SUCCESS(::NtQueryInformationProcess(m_Handle.get(), ProcessWindowInformation, buffer.get(), 1024, &len)))
		return info;

	auto p = reinterpret_cast<PROCESS_WINDOW_INFORMATION*>(buffer.get());
	info->Flags = p->WindowFlags;
	info->Title = std::wstring(p->WindowTitle, p->WindowTitleLength);
	return info;
}

int Process::GetMemoryPriority() const noexcept {
	int priority = -1;
	ULONG len;
	::NtQueryInformationProcess(m_Handle.get(), ProcessPagePriority, &priority, sizeof(priority), &len);
	return priority;
}

IoPriority Process::GetIoPriority() const noexcept {
	auto priority = IoPriority::Unknown;
	ULONG len;
	::NtQueryInformationProcess(m_Handle.get(), ProcessIoPriority, &priority, sizeof(priority), &len);
	return priority;
}

HANDLE Process::Handle() const noexcept {
	return m_Handle.get();
}

bool Process::IsElevated() const noexcept {
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_Handle.get(), TOKEN_QUERY, hToken.addressof()))
		return false;

	TOKEN_ELEVATION elevation;
	DWORD size;
	if (!NT_SUCCESS(::NtQueryInformationToken(hToken.get(), TokenElevation, &elevation, sizeof(elevation), &size)))
		return false;
	return elevation.TokenIsElevated ? true : false;
}

bool Process::Is64Bit() const noexcept {
	auto& info = SystemInformation::GetBasicSystemInfo();
	if (info.ProcessorArchitecture == ProcessorArchitecture::ARM || info.ProcessorArchitecture == ProcessorArchitecture::x86)
		return false;

	BOOL bit32 = FALSE;
	::IsWow64Process(m_Handle.get(), &bit32);
	return bit32;
}

std::wstring Process::GetWindowTitle() const {
	BYTE buffer[1024];
	ULONG len;
	auto status = ::NtQueryInformationProcess(m_Handle.get(), ProcessWindowInformation, buffer, 1024, &len);
	if (!NT_SUCCESS(status))
		return L"";

	auto name = reinterpret_cast<PROCESS_WINDOW_INFORMATION*>(buffer);
	return std::wstring(name->WindowTitle, name->WindowTitleLength / sizeof(WCHAR));
}

IntegrityLevel Process::GetIntegrityLevel() const noexcept {
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_Handle.get(), TOKEN_QUERY, hToken.addressof()))
		return IntegrityLevel::Error;

	BYTE buffer[256];
	DWORD len;
	if (!NT_SUCCESS(::NtQueryInformationToken(hToken.get(), TokenIntegrityLevel, buffer, 256, &len)))
		return IntegrityLevel::Error;

	auto integrity = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer);

	auto sid = integrity->Label.Sid;
	return (IntegrityLevel)(*::GetSidSubAuthority(sid, *::GetSidSubAuthorityCount(sid) - 1));
}


namespace {
	// the first token (quoted, or up to a space) and the rest, trimmed
	std::pair<std::wstring, std::wstring> SplitCommandLine(std::wstring const& commandLine) {
		auto start = commandLine.find_first_not_of(L" \t");
		if (start == std::wstring::npos)
			return {};
		size_t end;
		std::wstring file;
		if (commandLine[start] == L'"') {
			end = commandLine.find(L'"', start + 1);
			file = commandLine.substr(start + 1, end == std::wstring::npos ? std::wstring::npos : end - start - 1);
			end = end == std::wstring::npos ? commandLine.size() : end + 1;
		}
		else {
			end = commandLine.find_first_of(L" \t", start);
			if (end == std::wstring::npos)
				end = commandLine.size();
			file = commandLine.substr(start, end - start);
		}
		auto first = commandLine.find_first_not_of(L" \t", end);
		return { std::move(file), first == std::wstring::npos ? std::wstring() : commandLine.substr(first) };
	}
}

std::optional<uint32_t> Process::Run(std::wstring const& commandLine, bool elevated, HWND hOwner) {
	auto [file, args] = SplitCommandLine(commandLine);
	if (file.empty()) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		return std::nullopt;
	}
	SHELLEXECUTEINFO sei{ sizeof(sei) };
	sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
	sei.hwnd = hOwner;
	sei.lpVerb = elevated ? L"runas" : nullptr;
	sei.lpFile = file.c_str();
	sei.lpParameters = args.empty() ? nullptr : args.c_str();
	sei.nShow = SW_SHOWNORMAL;
	if (!::ShellExecuteEx(&sei))
		return std::nullopt;
	// none if a running process took it (a document opened in a window that was open)
	uint32_t pid = 0;
	if (sei.hProcess) {
		pid = ::GetProcessId(sei.hProcess);
		::CloseHandle(sei.hProcess);
	}
	return pid;
}

std::optional<uint32_t> Process::RunAs(std::wstring const& commandLine, std::wstring const& user, std::wstring const& password,
	bool loadProfile, bool netOnly) {
	// DOMAIN\user; a UPN (user@domain) goes as the user name with no domain; a bare name is a local account
	std::wstring name = user, domain;
	if (auto slash = user.find(L'\\'); slash != std::wstring::npos) {
		domain = user.substr(0, slash);
		name = user.substr(slash + 1);
	}
	else if (user.find(L'@') == std::wstring::npos)
		domain = L".";
	// CreateProcessWithLogonW may change the command line's buffer
	std::wstring cmd = commandLine;
	STARTUPINFO si{ sizeof(si) };
	PROCESS_INFORMATION pi;
	DWORD flags = netOnly ? LOGON_NETCREDENTIALS_ONLY : loadProfile ? LOGON_WITH_PROFILE : 0;
	if (!::CreateProcessWithLogonW(name.c_str(), domain.empty() ? nullptr : domain.c_str(), password.c_str(), flags, nullptr,
		cmd.data(), CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi))
		return std::nullopt;
	::CloseHandle(pi.hThread);
	::CloseHandle(pi.hProcess);
	return pi.dwProcessId;
}

std::unique_ptr<Process> Process::GetCurrent() {
	return std::make_unique<Process>(NtCurrentProcess());
}

Process::Process(HANDLE handle) noexcept : m_Handle(handle) {
}

std::unique_ptr<Process> Process::OpenById(uint32_t pid, ProcessAccessMask access) {
	auto handle = ::OpenProcess(static_cast<ACCESS_MASK>(access), FALSE, pid);
	return handle ? std::make_unique<Process>(handle) : nullptr;
}

std::unique_ptr<Process> Process::OpenById(uint32_t pid, int64_t createTime, ProcessAccessMask access) {
	auto process = OpenById(pid, access | ProcessAccessMask::QueryLimitedInformation);
	if (process && process->GetCreateTime() != createTime) {
		// another process with the same ID
		::SetLastError(ERROR_NOT_FOUND);
		return nullptr;
	}
	return process;
}

int64_t Process::GetCreateTime() const noexcept {
	FILETIME created, exited, kernel, user;
	if (!::GetProcessTimes(m_Handle.get(), &created, &exited, &kernel, &user))
		return 0;
	return (int64_t)ULARGE_INTEGER{ created.dwLowDateTime, created.dwHighDateTime }.QuadPart;
}

bool Process::Open(uint32_t pid, ProcessAccessMask access) noexcept {
	m_Handle.reset(::OpenProcess(static_cast<ACCESS_MASK>(access), FALSE, pid));
	return m_Handle != nullptr;
}

bool Process::IsValid() const noexcept {
	return m_Handle != nullptr;
}

std::wstring Process::GetFullImageName() const {
	DWORD size = MAX_PATH;
	WCHAR name[MAX_PATH];
	auto success = ::QueryFullProcessImageName(m_Handle.get(), 0, name, &size);
	return success ? std::wstring(name) : L"";
}

std::wstring Process::GetCommandLine() const {
	ULONG size = 8192;
	auto buffer = std::make_unique<BYTE[]>(size);
	auto status = ::NtQueryInformationProcess(m_Handle.get(), ProcessCommandLineInformation, buffer.get(), size, &size);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		// command lines can be up to 32K characters; size now holds the required length
		buffer = std::make_unique<BYTE[]>(size);
		status = ::NtQueryInformationProcess(m_Handle.get(), ProcessCommandLineInformation, buffer.get(), size, &size);
	}
	if (NT_SUCCESS(status)) {
		auto str = (UNICODE_STRING*)buffer.get();
		return std::wstring(str->Buffer, str->Length / sizeof(WCHAR));
	}
	return L"";
}

std::wstring Process::GetUserName() const noexcept {
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_Handle.get(), TOKEN_QUERY, hToken.addressof()))
		return L"";

	BYTE buffer[128];
	DWORD len;
	if (!NT_SUCCESS(::NtQueryInformationToken(hToken.get(), TokenUser, buffer, sizeof(buffer), &len)))
		return L"";

	auto user = reinterpret_cast<TOKEN_USER*>(buffer);
	DWORD userMax = TOKEN_USER_MAX_SIZE;
	wchar_t name[TOKEN_USER_MAX_SIZE];
	DWORD domainMax = 64;
	wchar_t domain[64];
	SID_NAME_USE use;
	if (!::LookupAccountSid(nullptr, user->User.Sid, name, &userMax, domain, &domainMax, &use))
		return L"";

	return std::wstring(domain) + L"\\" + name;
}

ProcessProtection Process::GetProtection() const noexcept {
	ProcessProtection protection{};
	ULONG len;
	::NtQueryInformationProcess(m_Handle.get(), ProcessProtectionInformation, &protection, sizeof(protection), &len);
	return protection;
}

bool Process::Terminate(uint32_t exitCode) noexcept {
	return NT_SUCCESS(NtTerminateProcess(m_Handle.get(), exitCode));
}

bool Process::Suspend() noexcept {
	return NT_SUCCESS(::NtSuspendProcess(m_Handle.get()));
}

bool Process::Resume() noexcept {
	return NT_SUCCESS(::NtResumeProcess(m_Handle.get()));
}

bool Process::IsImmersive() const noexcept {
	static const auto pIsImmersiveProcess = (decltype(::IsImmersiveProcess)*)::GetProcAddress(::GetModuleHandle(L"user32"), "IsImmersiveProcess");
	return pIsImmersiveProcess && pIsImmersiveProcess(m_Handle.get()) ? true : false;
}

bool Process::IsProtected() const noexcept {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsProtectedProcess;
}

bool Process::IsSecure() const noexcept {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsSecureProcess;
}

bool Process::IsSuspended() const noexcept {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsFrozen;
}

bool Process::IsInJob(HANDLE hJob) const noexcept {
	BOOL injob = FALSE;
	::IsProcessInJob(m_Handle.get(), hJob, &injob);
	return injob ? true : false;
}

bool Process::IsWow64Process() const noexcept {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsWow64Process ? true : false;
}

bool Process::IsPico() const noexcept {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsSubsystemProcess ? true : false;
}

bool Process::IsTerminated() const noexcept {
	return ::WaitForSingleObject(m_Handle.get(), 0) == WAIT_OBJECT_0;
}

bool Process::IsManaged() const noexcept {
	wil::unique_handle hProcess;
	if (!::DuplicateHandle(::GetCurrentProcess(), m_Handle.get(), ::GetCurrentProcess(), hProcess.addressof(),
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 0))
		return false;

	WCHAR filename[MAX_PATH];
	BOOL wow64 = FALSE;
	::IsWow64Process(hProcess.get(), &wow64);

	HMODULE hModule[64];
	DWORD needed;
	if (!::EnumProcessModulesEx(hProcess.get(), hModule, sizeof(hModule), &needed, wow64 ? LIST_MODULES_32BIT : LIST_MODULES_ALL))
		return false;

	auto count = std::min(_countof(hModule), needed / sizeof(HMODULE));

	for (int i = 0; i < count; i++) {
		if (::GetModuleFileNameEx(hProcess.get(), hModule[i], filename, MAX_PATH) == 0)
			continue;
			auto bs = ::wcsrchr(filename, L'\\');
			if (bs && (::_wcsicmp(bs, L"\\clr.dll") == 0 || ::_wcsicmp(bs, L"\\coreclr.dll") == 0 || ::_wcsicmp(bs, L"\\mscorwks.dll") == 0))
				return true;
	}
	return false;
}

bool Process::SetIoPriority(IoPriority priority) noexcept {
	// IO_PRIORITY_HINT: very low (0) to high (3)
	ULONG hint = (ULONG)priority;
	if (priority == IoPriority::High)
		SecurityHelper::EnablePrivilege(SE_INC_BASE_PRIORITY_NAME, true);
	auto status = ::NtSetInformationProcess(m_Handle.get(), ProcessIoPriority, &hint, sizeof(hint));
	if (!NT_SUCCESS(status))
		::SetLastError(::RtlNtStatusToDosError(status));
	return NT_SUCCESS(status);
}

bool Process::SetMemoryPriority(int priority) noexcept {
	MEMORY_PRIORITY_INFORMATION info{ (ULONG)priority };
	return ::SetProcessInformation(m_Handle.get(), ProcessMemoryPriority, &info, sizeof(info));
}

bool Process::GetAffinity(DWORD_PTR& mask, DWORD_PTR& systemMask) const noexcept {
	if (!::GetProcessAffinityMask(m_Handle.get(), &mask, &systemMask))
		return false;
	if (mask == 0) {
		::SetLastError(ERROR_NOT_SUPPORTED);
		return false;
	}
	return true;
}

bool Process::SetAffinity(DWORD_PTR mask) noexcept {
	return ::SetProcessAffinityMask(m_Handle.get(), mask);
}

std::vector<uint16_t> Process::GetGroups() const noexcept {
	std::vector<uint16_t> groups(64);
	USHORT count = (USHORT)groups.size();
	if (!::GetProcessGroupAffinity(m_Handle.get(), &count, groups.data())) {
		if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return {};
		groups.resize(count);
		if (!::GetProcessGroupAffinity(m_Handle.get(), &count, groups.data()))
			return {};
	}
	groups.resize(count);
	return groups;
}

namespace {
	// Windows 11 and Server 2022 on: looked up, so the library still loads on older systems
	using GetCpuSetMasksFn = BOOL(WINAPI*)(HANDLE, PGROUP_AFFINITY, USHORT, PUSHORT);
	using SetCpuSetMasksFn = BOOL(WINAPI*)(HANDLE, PGROUP_AFFINITY, USHORT);

	FARPROC Kernel32Function(PCSTR name) {
		return ::GetProcAddress(::GetModuleHandle(L"kernel32"), name);
	}
}

std::optional<std::vector<GROUP_AFFINITY>> Process::GetDefaultCpuSetMasks() const noexcept {
	static auto get = (GetCpuSetMasksFn)Kernel32Function("GetProcessDefaultCpuSetMasks");
	if (!get) {
		::SetLastError(ERROR_NOT_SUPPORTED);
		return {};
	}
	std::vector<GROUP_AFFINITY> masks(16);
	USHORT count = 0;
	while (!get(m_Handle.get(), masks.data(), (USHORT)masks.size(), &count)) {
		if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || count <= masks.size())
			return {};
		masks.resize(count);
	}
	masks.resize(count);
	return masks;
}

bool Process::SetDefaultCpuSetMasks(std::vector<GROUP_AFFINITY> const& masks) noexcept {
	static auto set = (SetCpuSetMasksFn)Kernel32Function("SetProcessDefaultCpuSetMasks");
	if (!set) {
		::SetLastError(ERROR_NOT_SUPPORTED);
		return false;
	}
	return set(m_Handle.get(), masks.empty() ? nullptr : const_cast<GROUP_AFFINITY*>(masks.data()), (USHORT)masks.size());
}

std::optional<bool> Process::GetEfficiencyMode() const noexcept {
	PROCESS_POWER_THROTTLING_STATE state{ PROCESS_POWER_THROTTLING_CURRENT_VERSION };
	if (!::GetProcessInformation(m_Handle.get(), ProcessPowerThrottling, &state, sizeof(state)))
		return std::nullopt;
	return (state.ControlMask & state.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED) != 0;
}

bool Process::SetEfficiencyMode(bool on) noexcept {
	PROCESS_POWER_THROTTLING_STATE state{ PROCESS_POWER_THROTTLING_CURRENT_VERSION };
	state.ControlMask = on ? PROCESS_POWER_THROTTLING_EXECUTION_SPEED : 0;
	state.StateMask = on ? PROCESS_POWER_THROTTLING_EXECUTION_SPEED : 0;
	return ::SetProcessInformation(m_Handle.get(), ProcessPowerThrottling, &state, sizeof(state))
		&& ::SetPriorityClass(m_Handle.get(), on ? IDLE_PRIORITY_CLASS : NORMAL_PRIORITY_CLASS);
}

ProcessStructures Process::GetStructures(HANDLE hProcess) {
	ProcessStructures result;
	PROCESS_BASIC_INFORMATION pbi;
	if (NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)))
		result.Peb = (uint64_t)pbi.PebBaseAddress;
	ULONG_PTR peb32 = 0;
	if (NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessWow64Information, &peb32, sizeof(peb32), nullptr)))
		result.Peb32 = peb32;

	HANDLE hThread = nullptr;
	for (;;) {
		// NtGetNextThread continues from the previous handle, so that one closes only after the call
		HANDLE hNext;
		auto status = ::NtGetNextThread(hProcess, hThread, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &hNext);
		if (hThread)
			::NtClose(hThread);
		if (!NT_SUCCESS(status))
			break;
		hThread = hNext;
		THREAD_BASIC_INFORMATION tbi;
		if (!NT_SUCCESS(::NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)) || !tbi.TebBaseAddress)
			continue;
		ThreadStructures t{ HandleToULong(tbi.ClientId.UniqueThread), (uint64_t)tbi.TebBaseAddress };
		// the stack's bounds are at the start of the TEB (NT_TIB)
		NT_TIB tib;
		if (::ReadProcessMemory(hProcess, tbi.TebBaseAddress, &tib, sizeof(tib), nullptr)) {
			t.StackBase = (uint64_t)tib.StackBase;
			t.StackLimit = (uint64_t)tib.StackLimit;
		}
		if (result.Peb32) {
			// WOW64 puts the 32-bit TEB two pages after the 64-bit one
			t.Teb32 = t.Teb + 0x2000;
			NT_TIB32 tib32;
			if (::ReadProcessMemory(hProcess, (void const*)t.Teb32, &tib32, sizeof(tib32), nullptr)) {
				t.Stack32Base = tib32.StackBase;
				t.Stack32Limit = tib32.StackLimit;
			}
		}
		result.Threads.push_back(t);
	}
	std::sort(result.Threads.begin(), result.Threads.end(), [](auto& t1, auto& t2) { return t1.ThreadId < t2.ThreadId; });
	return result;
}

std::vector<LoadedModule> Process::EnumLoadedModules(HANDLE hProcess) {
	std::vector<LoadedModule> result;
	std::vector<HMODULE> modules(256);
	DWORD needed = 0;
	while (::EnumProcessModulesEx(hProcess, modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL)
		&& needed > modules.size() * sizeof(HMODULE))
		modules.resize(needed / sizeof(HMODULE) + 16);
	modules.resize((std::min)(modules.size(), (size_t)needed / sizeof(HMODULE)));
	for (auto module : modules) {
		WCHAR path[1024];
		if (::GetModuleFileNameExW(hProcess, module, path, _countof(path)))
			result.push_back({ (uint64_t)module, path });
	}
	return result;
}

std::vector<std::pair<uint32_t, std::wstring>> Process::EnumProcessNames() {
	std::vector<std::pair<uint32_t, std::wstring>> processes;
	// INVALID_HANDLE_VALUE on failure, as unique_hfile expects
	wil::unique_hfile snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (!snapshot)
		return processes;
	PROCESSENTRY32W pe{ sizeof(pe) };
	for (BOOL ok = ::Process32FirstW(snapshot.get(), &pe); ok; ok = ::Process32NextW(snapshot.get(), &pe))
		if (pe.th32ProcessID)
			processes.push_back({ pe.th32ProcessID, pe.szExeFile });
	return processes;
}

WinSys::ProcessPriorityClass Process::GetPriorityClass() const noexcept {
	return static_cast<WinSys::ProcessPriorityClass>(::GetPriorityClass(m_Handle.get()));
}

bool Process::SetPriorityClass(WinSys::ProcessPriorityClass pc) noexcept {
	return ::SetPriorityClass(m_Handle.get(), static_cast<DWORD>(pc));
}

uint32_t Process::GetGdiObjectCount() const noexcept {
	return ::GetGuiResources(m_Handle.get(), GR_GDIOBJECTS);
}

uint32_t Process::GetPeakGdiObjectCount() const noexcept {
	return ::GetGuiResources(m_Handle.get(), GR_GDIOBJECTS_PEAK);
}

uint32_t Process::GetUserObjectCount() const noexcept {
	return ::GetGuiResources(m_Handle.get(), GR_USEROBJECTS);
}

uint32_t Process::GetPeakUserObjectCount() const noexcept {
	return ::GetGuiResources(m_Handle.get(), GR_USEROBJECTS_PEAK);
}

VirtualizationState Process::GetVirtualizationState() const noexcept {
	ULONG virt = 0;
	DWORD len;
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_Handle.get(), TOKEN_QUERY, hToken.addressof()))
		return VirtualizationState::Unknown;

	if (!NT_SUCCESS(::NtQueryInformationToken(hToken.get(), TokenVirtualizationAllowed, &virt, sizeof(virt), &len)))
		return VirtualizationState::Unknown;

	if (!virt)
		return VirtualizationState::NotAllowed;

	if (NT_SUCCESS(::NtQueryInformationToken(hToken.get(), TokenVirtualizationEnabled, &virt, sizeof(virt), &len)))
		return virt ? VirtualizationState::Enabled : VirtualizationState::Disabled;

	return VirtualizationState::Unknown;
}

HANDLE Process::GetNextThread(HANDLE hThread, ThreadAccessMask access) {
	HANDLE hNewThread{ nullptr };
	::NtGetNextThread(m_Handle.get(), hThread, static_cast<ACCESS_MASK>(access), 0, 0, &hNewThread);
	return hNewThread;
}

DpiAwareness Process::GetDpiAwareness() const noexcept {
	static const auto pGetProcessDpiAware = (decltype(::GetProcessDpiAwareness)*)::GetProcAddress(::GetModuleHandle(L"shcore"), "GetProcessDpiAwareness");

	if (!m_Handle || pGetProcessDpiAware == nullptr)
		return DpiAwareness::None;

	DpiAwareness da = DpiAwareness::None;
	pGetProcessDpiAware(m_Handle.get(), reinterpret_cast<PROCESS_DPI_AWARENESS*>(&da));
	return da;
}

std::wstring Process::GetCurrentDirectory() const noexcept {
	wil::unique_handle h;
	if (!::DuplicateHandle(::GetCurrentProcess(), m_Handle.get(), ::GetCurrentProcess(), h.addressof(), PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, 0))
		return L"";
	return GetCurrentDirectory(h.get());
}

std::wstring Process::GetCurrentDirectory(HANDLE hProcess) noexcept {
	std::wstring path;
	PEB peb;
	if (!GetProcessPeb(hProcess, &peb))
		return path;

	RTL_USER_PROCESS_PARAMETERS processParams;
	if (!::ReadProcessMemory(hProcess, peb.ProcessParameters, &processParams, sizeof(processParams), nullptr))
		return path;
	
	path.resize(processParams.CurrentDirectory.DosPath.Length / sizeof(WCHAR) + 1);
	if (!::ReadProcessMemory(hProcess, processParams.CurrentDirectory.DosPath.Buffer, path.data(), processParams.CurrentDirectory.DosPath.Length, nullptr))
		return L"";

	return path;
}

std::vector<std::pair<std::wstring, std::wstring>> Process::GetEnvironment(HANDLE hProcess) noexcept {
	std::vector<std::pair<std::wstring, std::wstring>> env;

	// the block and its size from the process parameters: a WOW64 process's own (32-bit) ones, which its code updates
	PVOID address = nullptr;
	SIZE_T size = 0;
	ULONG_PTR peb32 = 0;
	if (NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessWow64Information, &peb32, sizeof(peb32), nullptr)) && peb32) {
		PEB32 peb;
		RTL_USER_PROCESS_PARAMETERS32 params;
		if (!::ReadProcessMemory(hProcess, (PVOID)peb32, &peb, sizeof(peb), nullptr)
			|| !::ReadProcessMemory(hProcess, ULongToPtr(peb.ProcessParameters), &params, sizeof(params), nullptr))
			return env;
		address = ULongToPtr(params.Environment);
		size = params.EnvironmentSize;
	}
	else {
		PEB peb;
		RTL_USER_PROCESS_PARAMETERS params;
		if (!GetProcessPeb(hProcess, &peb) || !::ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), nullptr))
			return env;
		address = params.Environment;
		size = params.EnvironmentSize;
	}
	// a sanity limit: the block is normally a few KB
	if (address == nullptr || size < sizeof(WCHAR) || size > (16 << 20))
		return env;

	// two terminators past the end, in case the block lacks its own
	std::vector<WCHAR> buffer(size / sizeof(WCHAR) + 2);
	if (!::ReadProcessMemory(hProcess, address, buffer.data(), size, nullptr))
		return env;

	env.reserve(64);
	auto end = buffer.data() + size / sizeof(WCHAR);
	for (auto p = buffer.data(); p < end && *p; ) {
		std::wstring_view entry(p, ::wcsnlen(p, end - p));
		p += entry.size() + 1;
		// a name may start with '=' (the hidden per-drive current directories, such as "=C:=C:\Windows")
		auto equal = entry.find(L'=', 1);
		if (equal == std::wstring_view::npos)
			env.emplace_back(std::wstring(entry), std::wstring());
		else
			env.emplace_back(std::wstring(entry.substr(0, equal)), std::wstring(entry.substr(equal + 1)));
	}
	return env;
}

std::vector<std::pair<std::wstring, std::wstring>> WinSys::Process::GetEnvironment() const noexcept {
	return GetEnvironment(m_Handle.get());
}
