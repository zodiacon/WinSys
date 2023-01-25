#include "pch.h"
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
	if (!::GetTokenInformation(hToken.get(), TokenElevation, &elevation, sizeof(elevation), &size))
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
	if (!::GetTokenInformation(hToken.get(), TokenIntegrityLevel, buffer, 256, &len))
		return IntegrityLevel::Error;

	auto integrity = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer);

	auto sid = integrity->Label.Sid;
	return (IntegrityLevel)(*::GetSidSubAuthority(sid, *::GetSidSubAuthorityCount(sid) - 1));
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
	if (!::GetTokenInformation(hToken.get(), TokenUser, buffer, sizeof(buffer), &len))
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

	int count = min(_countof(hModule), needed / sizeof(HMODULE));

	for (int i = 0; i < count; i++) {
		if (::GetModuleFileNameEx(hProcess.get(), hModule[i], filename, MAX_PATH) == 0)
			continue;
			auto bs = ::wcsrchr(filename, L'\\');
			if (bs && (::_wcsicmp(bs, L"\\clr.dll") == 0 || ::_wcsicmp(bs, L"\\coreclr.dll") == 0 || ::_wcsicmp(bs, L"\\mscorwks.dll") == 0))
				return true;
	}
	return false;
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

	if (!::GetTokenInformation(hToken.get(), TokenVirtualizationAllowed, &virt, sizeof(virt), &len))
		return VirtualizationState::Unknown;

	if (!virt)
		return VirtualizationState::NotAllowed;

	if (::GetTokenInformation(hToken.get(), TokenVirtualizationEnabled, &virt, sizeof(virt), &len))
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

	PEB peb;
	if(!GetProcessPeb(hProcess, &peb))
		return env;

	RTL_USER_PROCESS_PARAMETERS processParams;
	if (!::ReadProcessMemory(hProcess, peb.ProcessParameters, &processParams, sizeof(processParams), nullptr))
		return env;

	BYTE buffer[1 << 16];
	int size = sizeof(buffer);
	for(;;) {
		if (::ReadProcessMemory(hProcess, processParams.Environment, buffer, size, nullptr))
			break;
		size -= 1 << 12;
	}

	env.reserve(64);

	for (auto p = (PWSTR)buffer; *p; ) {
		std::pair<std::wstring, std::wstring> var;
		auto equal = wcschr(p, L'=');
		assert(equal);
		if (!equal)
			break;
		*equal = L'\0';
		var.first = p;
		p += ::wcslen(p) + 1;
		var.second = p;
		p += ::wcslen(p) + 1;
		env.push_back(std::move(var));
	}

	return env;
}

std::vector<std::pair<std::wstring, std::wstring>> WinSys::Process::GetEnvironment() const noexcept {
	return GetEnvironment(m_Handle.get());
}
