#include "pch.h"
#include <atomic>
#include <wil/resource.h>
#include "Handles.h"
#include "Sid.h"

using namespace WinSys;

namespace {
	std::vector<std::wstring> LoadTypeNames() {
		std::vector<std::wstring> names;
		ULONG size = 1 << 16;
		std::unique_ptr<BYTE[]> buffer;
		NTSTATUS status;
		for (;;) {
			buffer = std::make_unique<BYTE[]>(size);
			ULONG needed = 0;
			status = ::NtQueryObject(nullptr, ObjectTypesInformation, buffer.get(), size, &needed);
			if (status != STATUS_INFO_LENGTH_MISMATCH)
				break;
			size = std::max(size * 2, needed + 4096);
		}
		if (!NT_SUCCESS(status))
			return names;

		auto types = reinterpret_cast<OBJECT_TYPES_INFORMATION const*>(buffer.get());
		// the entries follow the header, each followed by its name, aligned to a pointer
		auto align = [](ULONG_PTR p) { return (p + sizeof(ULONG_PTR) - 1) & ~(sizeof(ULONG_PTR) - 1); };
		auto type = reinterpret_cast<OBJECT_TYPE_INFORMATION const*>(align((ULONG_PTR)types + sizeof(*types)));
		for (ULONG i = 0; i < types->NumberOfTypes; i++) {
			auto index = type->TypeIndex;
			if (index >= names.size())
				names.resize(index + 1);
			names[index].assign(type->TypeName.Buffer, type->TypeName.Length / sizeof(WCHAR));
			type = reinterpret_cast<OBJECT_TYPE_INFORMATION const*>(
				align((ULONG_PTR)type + sizeof(OBJECT_TYPE_INFORMATION) + type->TypeName.MaximumLength));
		}
		return names;
	}
}

std::wstring const& ObjectTypes::GetName(uint16_t typeIndex) {
	// the types are fixed while the system runs
	static const std::vector<std::wstring> names = LoadTypeNames();
	static const std::wstring empty;
	return typeIndex < names.size() ? names[typeIndex] : empty;
}

std::optional<std::vector<HandleEntry>> HandleEnumerator::EnumProcessHandles(uint32_t pid) {
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
	if (!hProcess)
		return std::nullopt;

	ULONG size = 1 << 14;
	std::unique_ptr<BYTE[]> buffer;
	NTSTATUS status;
	for (;;) {
		buffer = std::make_unique<BYTE[]>(size);
		ULONG needed = 0;
		status = ::NtQueryInformationProcess(hProcess.get(), ProcessHandleInformation, buffer.get(), size, &needed);
		if (status != STATUS_INFO_LENGTH_MISMATCH)
			break;
		// handles may be opened in between: some room
		size = needed + 4096;
	}
	if (!NT_SUCCESS(status))
		return std::nullopt;

	auto info = reinterpret_cast<PROCESS_HANDLE_SNAPSHOT_INFORMATION const*>(buffer.get());
	std::vector<HandleEntry> handles;
	handles.reserve(info->NumberOfHandles);
	for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
		auto& h = info->Handles[i];
		handles.push_back({ (uint64_t)h.HandleValue, nullptr, h.GrantedAccess, h.HandleAttributes, (uint16_t)h.ObjectTypeIndex });
	}
	return handles;
}

std::optional<std::vector<HandleEntry>> HandleEnumerator::EnumProcessHandlesWithAddresses(uint32_t pid) {
	if (m_Size == 0) {
		m_Size = 1 << 22;
		m_Buffer = std::make_unique<uint8_t[]>(m_Size);
	}
	NTSTATUS status;
	for (;;) {
		ULONG needed = 0;
		status = ::NtQuerySystemInformation(SystemExtendedHandleInformation, m_Buffer.get(), (ULONG)m_Size, &needed);
		if (status != STATUS_INFO_LENGTH_MISMATCH)
			break;
		// handles come and go between the calls: some room
		m_Size = std::max<size_t>(m_Size * 2, needed + (1 << 16));
		m_Buffer = std::make_unique<uint8_t[]>(m_Size);
	}
	if (!NT_SUCCESS(status))
		return std::nullopt;

	auto info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX const*>(m_Buffer.get());
	std::vector<HandleEntry> handles;
	for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
		auto& h = info->Handles[i];
		if (HandleToULong(h.UniqueProcessId) == pid)
			handles.push_back({ (uint64_t)h.HandleValue, h.Object, h.GrantedAccess, h.HandleAttributes, h.ObjectTypeIndex });
	}
	return handles;
}

struct ObjectNameQuery::Worker {
	wil::unique_event Request{ wil::EventOptions::None }, Done{ wil::EventOptions::None };
	HANDLE Target{ nullptr };
	std::wstring Name;
	std::atomic<bool> Abandoned{ false }, Exit{ false };

	void Run() {
		std::unique_ptr<BYTE[]> buffer;
		ULONG size = 0;
		for (;;) {
			::WaitForSingleObject(Request.get(), INFINITE);
			if (Exit)
				break;
			Name.clear();
			for (;;) {
				if (size == 0 || !buffer) {
					size = size ? size : 2048;
					buffer = std::make_unique<BYTE[]>(size);
				}
				ULONG needed = 0;
				auto status = ::NtQueryObject(Target, ObjectNameInformation, buffer.get(), size, &needed);
				if ((status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW) && needed > size) {
					size = needed + 64;
					buffer.reset();
					continue;
				}
				if (NT_SUCCESS(status)) {
					auto name = reinterpret_cast<OBJECT_NAME_INFORMATION const*>(buffer.get());
					if (name->Name.Buffer)
						Name.assign(name->Name.Buffer, name->Name.Length / sizeof(WCHAR));
				}
				break;
			}
			if (Abandoned)
				break;	// the caller timed out and went on without us
			Done.SetEvent();
		}
	}

	static DWORD WINAPI ThreadProc(void* param) {
		// the thread keeps the worker alive, as an abandoned worker outlives its ObjectNameQuery
		std::unique_ptr<std::shared_ptr<Worker>> self(static_cast<std::shared_ptr<Worker>*>(param));
		(*self)->Run();
		return 0;
	}

	static std::shared_ptr<Worker> Start() {
		auto worker = std::make_shared<Worker>();
		auto param = new std::shared_ptr<Worker>(worker);
		wil::unique_handle hThread(::CreateThread(nullptr, 64 << 10, ThreadProc, param, 0, nullptr));
		if (!hThread) {
			delete param;
			return nullptr;
		}
		return worker;
	}
};

ObjectNameQuery::ObjectNameQuery() = default;

ObjectNameQuery::~ObjectNameQuery() {
	if (m_Worker) {
		m_Worker->Exit = true;
		m_Worker->Request.SetEvent();
	}
}

std::optional<std::wstring> ObjectNameQuery::GetName(HANDLE handle, uint32_t timeoutMs) {
	if (!m_Worker && !(m_Worker = Worker::Start()))
		return std::nullopt;

	m_Worker->Target = handle;
	m_Worker->Request.SetEvent();
	if (::WaitForSingleObject(m_Worker->Done.get(), timeoutMs) == WAIT_OBJECT_0)
		return std::move(m_Worker->Name);

	// stuck in the query: leave it, the next request gets a new worker. It exits when the query returns, or right away
	// if it finished just after the timeout and is waiting for another request
	m_Worker->Abandoned = true;
	m_Worker->Exit = true;
	m_Worker->Request.SetEvent();
	m_Worker.reset();
	m_Abandoned++;
	return std::nullopt;
}

int ObjectNameQuery::GetAbandonedCount() const {
	return m_Abandoned;
}

std::wstring HandleNames::RegistryName(std::wstring name) {
	// \REGISTRY\MACHINE\... and \REGISTRY\USER\<SID>\... as the registry editor shows them
	static const std::wstring currentUser = [] {
		std::wstring sid;
		HANDLE hToken;
		if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			BYTE buffer[256];
			DWORD len;
			if (NT_SUCCESS(::NtQueryInformationToken(hToken, TokenUser, buffer, sizeof(buffer), &len)))
				sid = L"\\REGISTRY\\USER\\" + Sid(reinterpret_cast<TOKEN_USER*>(buffer)->User.Sid).AsString();
			::CloseHandle(hToken);
		}
		return sid;
	}();
	auto replace = [&](std::wstring const& prefix, PCWSTR with) {
		if (prefix.empty() || ::_wcsnicmp(name.c_str(), prefix.c_str(), prefix.size()) != 0)
			return false;
		// the whole prefix or up to a backslash, not part of a longer name
		if (name.size() > prefix.size() && name[prefix.size()] != L'\\')
			return false;
		name = with + name.substr(prefix.size());
		return true;
	};
	// the first that matches
	(void)(replace(currentUser + L"_Classes", L"HKCU\\Software\\Classes") || replace(currentUser, L"HKCU")
		|| replace(L"\\REGISTRY\\MACHINE", L"HKLM") || replace(L"\\REGISTRY\\USER", L"HKU"));
	return name;
}

DosNames::DosNames() {
	auto drives = ::GetLogicalDrives();
	for (int drive = 0; drives; drive++, drives >>= 1) {
		WCHAR letter[] = L"X:";
		letter[0] = WCHAR(L'A' + drive);
		WCHAR device[MAX_PATH];
		if ((drives & 1) && ::QueryDosDevice(letter, device, _countof(device)))
			m_Devices.push_back({ std::wstring(device) + L"\\", std::wstring(letter) + L"\\" });
	}
}

std::wstring DosNames::Convert(std::wstring const& name) const {
	for (auto& [device, letter] : m_Devices)
		if (::_wcsnicmp(name.c_str(), device.c_str(), device.size()) == 0)
			return letter + name.substr(device.size());
	return name;
}

std::wstring HandleNames::QueryName(HANDLE hProcess, HandleEntry const& entry, ObjectNameQuery& nameQuery, DosNames const& dosNames,
	ProcessNameLookup processName, bool queryFiles) {
	if (!hProcess)
		return L"";
	auto& type = ObjectTypes::GetName(entry.TypeIndex);
	bool file = type == L"File";
	if (file && !queryFiles)
		return L"";

	// a copy of the handle in this process. Processes and threads are queried for their IDs, which the handle's own
	// access may not allow, so they're duplicated with the access that needs first
	wil::unique_handle h;
	auto source = (HANDLE)(ULONG_PTR)entry.Value;
	DWORD queryAccess = type == L"Process" ? PROCESS_QUERY_LIMITED_INFORMATION : type == L"Thread" ? THREAD_QUERY_LIMITED_INFORMATION : 0;
	if ((!queryAccess || !::DuplicateHandle(hProcess, source, ::GetCurrentProcess(), h.addressof(), queryAccess, FALSE, 0))
		&& !::DuplicateHandle(hProcess, source, ::GetCurrentProcess(), h.addressof(), 0, FALSE, DUPLICATE_SAME_ACCESS))
		return L"";

	// processes and threads have no names: their IDs and image names are more useful
	auto processText = [&](DWORD pid, HANDLE hTarget) {
		std::wstring name = processName ? processName(pid) : L"";
		if (name.empty() && hTarget) {
			// not known (it may have exited): the image path from the handle
			WCHAR path[MAX_PATH];
			DWORD size = _countof(path);
			if (::QueryFullProcessImageName(hTarget, 0, path, &size)) {
				auto slash = wcsrchr(path, L'\\');
				name = slash ? slash + 1 : path;
			}
		}
		return L"PID: " + std::to_wstring(pid) + (name.empty() ? L"" : L", " + name);
	};
	if (type == L"Process") {
		if (auto pid = ::GetProcessId(h.get()))
			return processText(pid, h.get());
		return L"";
	}
	if (type == L"Thread") {
		if (auto tid = ::GetThreadId(h.get()))
			return L"TID: " + std::to_wstring(tid) + L", " + processText(::GetProcessIdOfThread(h.get()), nullptr);
		return L"";
	}
	if (type == L"Token") {
		// the user, and the logon session
		BYTE buffer[256];
		DWORD len;
		TOKEN_STATISTICS stats;
		if (NT_SUCCESS(::NtQueryInformationToken(h.get(), TokenUser, buffer, sizeof(buffer), &len))
			&& NT_SUCCESS(::NtQueryInformationToken(h.get(), TokenStatistics, &stats, sizeof(stats), &len)))
		{
			WCHAR session[16];
			::StringCchPrintf(session, _countof(session), L":%x", stats.AuthenticationId.LowPart);
			return Sid(reinterpret_cast<TOKEN_USER*>(buffer)->User.Sid).UserName() + session;
		}
		return L"";
	}

	std::wstring name;
	if (file) {
		// a file opened for synchronous I/O blocks the query while I/O is in progress (a pipe being read): a worker
		// thread with a timeout
		auto result = nameQuery.GetName(h.get());
		if (!result || result->empty())
			return L"";
		return dosNames.Convert(*result);
	}
	// other objects' queries don't block
	BYTE buffer[2048];
	ULONG len;
	if (!NT_SUCCESS(::NtQueryObject(h.get(), ObjectNameInformation, buffer, sizeof(buffer), &len)))
		return L"";
	auto& info = *reinterpret_cast<OBJECT_NAME_INFORMATION const*>(buffer);
	if (!info.Name.Buffer || info.Name.Length == 0)
		return L"";
	name.assign(info.Name.Buffer, info.Name.Length / sizeof(WCHAR));
	return type == L"Key" ? RegistryName(std::move(name)) : name;
}

bool HandleNames::CloseInProcess(HANDLE hProcess, uint64_t value, std::wstring const& type) {
	// the handle value may have been closed and reused since it was listed: the object's type tells
	auto source = (HANDLE)(ULONG_PTR)value;
	wil::unique_handle copy;
	bool same = false;
	if (::DuplicateHandle(hProcess, source, ::GetCurrentProcess(), copy.addressof(), 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		BYTE buffer[1024];
		if (NT_SUCCESS(::NtQueryObject(copy.get(), ObjectTypeInformation, buffer, sizeof(buffer), nullptr))) {
			auto& info = *reinterpret_cast<OBJECT_TYPE_INFORMATION const*>(buffer);
			same = type == std::wstring_view(info.TypeName.Buffer, info.TypeName.Length / sizeof(WCHAR));
		}
	}
	if (!same) {
		::SetLastError(ERROR_INVALID_HANDLE);
		return false;
	}
	copy.reset();
	return ::DuplicateHandle(hProcess, source, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
}
