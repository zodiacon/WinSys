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

#ifdef WINSYS_NAMESPACE
using namespace WinSys;
#endif

uint32_t Process::GetId() const {
	return ::GetProcessId(m_handle.get());
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
	if (!NT_SUCCESS(::NtQueryInformationProcess(m_handle.get(), ProcessWindowInformation, buffer.get(), 1024, &len)))
		return info;

	auto p = reinterpret_cast<PROCESS_WINDOW_INFORMATION*>(buffer.get());
	info->Flags = p->WindowFlags;
	info->Title = std::wstring(p->WindowTitle, p->WindowTitleLength);
	return info;
}

int Process::GetMemoryPriority() const {
	int priority = -1;
	ULONG len;
	::NtQueryInformationProcess(m_handle.get(), ProcessPagePriority, &priority, sizeof(priority), &len);
	return priority;
}

IoPriority Process::GetIoPriority() const {
	auto priority = IoPriority::Unknown;
	ULONG len;
	::NtQueryInformationProcess(m_handle.get(), ProcessIoPriority, &priority, sizeof(priority), &len);
	return priority;
}

HANDLE Process::Handle() const {
	return m_handle.get();
}

bool Process::IsElevated() const {
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_handle.get(), TOKEN_QUERY, hToken.addressof()))
		return false;

	TOKEN_ELEVATION elevation;
	DWORD size;
	if (!::GetTokenInformation(hToken.get(), TokenElevation, &elevation, sizeof(elevation), &size))
		return false;
	return elevation.TokenIsElevated ? true : false;
}

bool Process::Is64Bit() const {
	auto& info = SystemInformation::GetBasicSystemInfo();
	if (info.ProcessorArchitecture == ProcessorArchitecture::ARM || info.ProcessorArchitecture == ProcessorArchitecture::x86)
		return false;

	BOOL bit32 = FALSE;
	::IsWow64Process(m_handle.get(), &bit32);
	return bit32;
}

std::wstring Process::GetWindowTitle() const {
	BYTE buffer[1024];
	ULONG len;
	auto status = ::NtQueryInformationProcess(m_handle.get(), ProcessWindowInformation, buffer, 1024, &len);
	if (!NT_SUCCESS(status))
		return L"";

	auto name = reinterpret_cast<PROCESS_WINDOW_INFORMATION*>(buffer);
	return std::wstring(name->WindowTitle, name->WindowTitleLength / sizeof(WCHAR));
}

IntegrityLevel Process::GetIntegrityLevel() const {
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_handle.get(), TOKEN_QUERY, hToken.addressof()))
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

Process::Process(HANDLE handle) : m_handle(handle) {
}

std::unique_ptr<Process> Process::OpenById(uint32_t pid, ProcessAccessMask access) {
	auto handle = ::OpenProcess(static_cast<ACCESS_MASK>(access), FALSE, pid);
	return handle ? std::make_unique<Process>(handle) : nullptr;
}

bool Process::Open(uint32_t pid, ProcessAccessMask access) {
	m_handle.reset(::OpenProcess(static_cast<ACCESS_MASK>(access), FALSE, pid));
	return m_handle != nullptr;
}

bool Process::IsValid() const {
	return m_handle != nullptr;
}

std::wstring Process::GetFullImageName() const {
	DWORD size = MAX_PATH;
	WCHAR name[MAX_PATH];
	auto success = ::QueryFullProcessImageName(m_handle.get(), 0, name, &size);
	return success ? std::wstring(name) : L"";
}

std::wstring Process::GetCommandLine() const {
	ULONG size = 8192;
	auto buffer = std::make_unique<BYTE[]>(size);
	auto status = ::NtQueryInformationProcess(m_handle.get(), ProcessCommandLineInformation, buffer.get(), size, &size);
	if (NT_SUCCESS(status)) {
		auto str = (UNICODE_STRING*)buffer.get();
		return std::wstring(str->Buffer, str->Length / sizeof(WCHAR));
	}
	return L"";
}

std::wstring Process::GetUserName() const {
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_handle.get(), TOKEN_QUERY, hToken.addressof()))
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

ProcessProtection Process::GetProtection() const {
	ProcessProtection protection{};
	ULONG len;
	::NtQueryInformationProcess(m_handle.get(), ProcessProtectionInformation, &protection, sizeof(protection), &len);
	return protection;
}

bool Process::Terminate(uint32_t exitCode) {
	return NT_SUCCESS(NtTerminateProcess(m_handle.get(), exitCode));
}

bool Process::Suspend() {
	return NT_SUCCESS(::NtSuspendProcess(m_handle.get()));
}

bool Process::Resume() {
	return NT_SUCCESS(::NtResumeProcess(m_handle.get()));
}

bool Process::IsImmersive() const noexcept {
	static const auto pIsImmersiveProcess = (decltype(::IsImmersiveProcess)*)::GetProcAddress(::GetModuleHandle(L"user32"), "IsImmersiveProcess");
	return pIsImmersiveProcess && pIsImmersiveProcess(m_handle.get()) ? true : false;
}

bool Process::IsProtected() const {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsProtectedProcess;
}

bool Process::IsSecure() const {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsSecureProcess;
}

bool Process::IsSuspended() const {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsFrozen;
}

bool Process::IsInJob(HANDLE hJob) const {
	BOOL injob = FALSE;
	::IsProcessInJob(m_handle.get(), hJob, &injob);
	return injob ? true : false;
}

bool Process::IsWow64Process() const {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsWow64Process ? true : false;
}

bool Process::IsPico() const {
	PROCESS_EXTENDED_BASIC_INFORMATION info;
	if (!GetExtendedInfo(Handle(), &info))
		return false;

	return info.IsSubsystemProcess ? true : false;
}

bool Process::IsTerminated() const {
	return ::WaitForSingleObject(m_handle.get(), 0) == WAIT_OBJECT_0;
}

bool Process::IsManaged() const {
	wil::unique_handle hProcess;
	if (!::DuplicateHandle(::GetCurrentProcess(), m_handle.get(), ::GetCurrentProcess(), hProcess.addressof(),
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

WinSys::ProcessPriorityClass Process::GetPriorityClass() const {
	return static_cast<WinSys::ProcessPriorityClass>(::GetPriorityClass(m_handle.get()));
}

bool Process::SetPriorityClass(WinSys::ProcessPriorityClass pc) {
	return ::SetPriorityClass(m_handle.get(), static_cast<DWORD>(pc));
}

uint32_t Process::GetGdiObjectCount() const {
	return ::GetGuiResources(m_handle.get(), GR_GDIOBJECTS);
}

uint32_t Process::GetPeakGdiObjectCount() const {
	return ::GetGuiResources(m_handle.get(), GR_GDIOBJECTS_PEAK);
}

uint32_t Process::GetUserObjectCount() const {
	return ::GetGuiResources(m_handle.get(), GR_USEROBJECTS);
}

uint32_t Process::GetPeakUserObjectCount() const {
	return ::GetGuiResources(m_handle.get(), GR_USEROBJECTS_PEAK);
}

VirtualizationState Process::GetVirtualizationState() const {
	ULONG virt = 0;
	DWORD len;
	wil::unique_handle hToken;
	if (!::OpenProcessToken(m_handle.get(), TOKEN_QUERY, hToken.addressof()))
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
	::NtGetNextThread(m_handle.get(), hThread, static_cast<ACCESS_MASK>(access), 0, 0, &hNewThread);
	return hNewThread;
}

DpiAwareness Process::GetDpiAwareness() const {
	static const auto pGetProcessDpiAware = (decltype(::GetProcessDpiAwareness)*)::GetProcAddress(::GetModuleHandle(L"shcore"), "GetProcessDpiAwareness");

	if (!m_handle || pGetProcessDpiAware == nullptr)
		return DpiAwareness::None;

	DpiAwareness da = DpiAwareness::None;
	pGetProcessDpiAware(m_handle.get(), reinterpret_cast<PROCESS_DPI_AWARENESS*>(&da));
	return da;
}

std::wstring Process::GetCurrentDirectory() const {
	wil::unique_handle h;
	if (!::DuplicateHandle(::GetCurrentProcess(), m_handle.get(), ::GetCurrentProcess(), h.addressof(), PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, 0))
		return L"";
	return GetCurrentDirectory(h.get());
}

std::wstring Process::GetCurrentDirectory(HANDLE hProcess) {
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

std::vector<std::pair<std::wstring, std::wstring>> Process::GetEnvironment(HANDLE hProcess) {
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
