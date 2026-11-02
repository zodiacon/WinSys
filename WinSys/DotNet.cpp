#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include "DotNet.h"
#include "EtwSession.h"
#include <wil/resource.h>
#include <algorithm>

using namespace WinSys;

bool DotNetInfo::HasFrameworkRuntime(uint32_t pid, uint32_t sessionId) {
	for (auto name : { L"Cor_Private_IPCBlock_v4_", L"Cor_Private_IPCBlock_" }) {
		auto path = (sessionId == 0 ? std::wstring(L"\\BaseNamedObjects\\")
			: L"\\Sessions\\" + std::to_wstring(sessionId) + L"\\BaseNamedObjects\\") + name + std::to_wstring(pid);
		UNICODE_STRING uname;
		::RtlInitUnicodeString(&uname, path.c_str());
		OBJECT_ATTRIBUTES attr;
		InitializeObjectAttributes(&attr, &uname, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		HANDLE hSection;
		auto status = ::NtOpenSection(&hSection, SECTION_QUERY, &attr);
		if (NT_SUCCESS(status))
			::NtClose(hSection);
		// another user's section exists even if it can't be opened
		if (NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED)
			return true;
	}
	return false;
}

std::unordered_set<uint32_t> DotNetInfo::GetCoreRuntimeProcesses() {
	std::unordered_set<uint32_t> pids;
	const std::wstring_view prefix = L"dotnet-diagnostic-";
	WIN32_FIND_DATA fd;
	wil::unique_hfind hFind(::FindFirstFile(L"\\\\.\\pipe\\*", &fd));
	if (!hFind)
		return pids;
	do {
		if (std::wstring_view(fd.cFileName).starts_with(prefix))
			if (auto pid = ::wcstoul(fd.cFileName + prefix.size(), nullptr, 10))
				pids.insert(pid);
	} while (::FindNextFile(hFind.get(), &fd));
	return pids;
}

bool DotNetInfo::HasRuntimeModule(uint32_t pid) {
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
	if (!hProcess)
		return false;
	std::vector<HMODULE> modules(512);
	DWORD needed = 0;
	for (;;) {
		if (!::EnumProcessModulesEx(hProcess.get(), modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL))
			return false;
		if (needed <= modules.size() * sizeof(HMODULE))
			break;
		modules.resize(needed / sizeof(HMODULE) + 64);
	}
	modules.resize(needed / sizeof(HMODULE));
	for (auto hModule : modules) {
		WCHAR name[MAX_PATH];
		if (::GetModuleBaseNameW(hProcess.get(), hModule, name, _countof(name))
			&& (_wcsicmp(name, L"clr.dll") == 0 || _wcsicmp(name, L"coreclr.dll") == 0 || _wcsicmp(name, L"mscorwks.dll") == 0))
			return true;
	}
	return false;
}

namespace {
	// Microsoft-Windows-DotNETRuntimeRundown
	const GUID RundownProvider = { 0xA669021C, 0xC450, 0x4609, { 0xA0, 0x35, 0x5A, 0xF5, 0x9A, 0xF4, 0xDF, 0x18 } };
	const ULONGLONG LoaderRundownKeyword = 0x8, StartRundownKeyword = 0x40;

	enum RundownEvent : USHORT {
		DCStartComplete = 145, ModuleDCStart = 153, AssemblyDCStart = 155, AppDomainDCStart = 157, RuntimeInformationDCStart = 187,
	};

	// reads an event's payload in order; a read past its end makes Ok false (and gives zeros)
	struct PayloadReader {
		BYTE const* Pos, * End;
		bool Ok{ true };

		template<typename T>
		T Get() {
			T value{};
			if (End - Pos < (ptrdiff_t)sizeof(T)) {
				Ok = false;
				Pos = End;
				return value;
			}
			memcpy(&value, Pos, sizeof(T));
			Pos += sizeof(T);
			return value;
		}

		std::wstring String() {
			auto start = reinterpret_cast<WCHAR const*>(Pos);
			auto count = (End - Pos) / (ptrdiff_t)sizeof(WCHAR);
			for (ptrdiff_t i = 0; i < count; i++) {
				if (start[i] == 0) {
					Pos += (i + 1) * sizeof(WCHAR);
					return std::wstring(start, i);
				}
			}
			Ok = false;
			Pos = End;
			return L"";
		}
	};

	struct RundownContext {
		uint32_t Pid;
		DotNetProcessDetails Details;
		std::vector<uint16_t> Completed;	// the runtimes (CLR instance IDs) whose rundown is done
		HANDLE hDone;
	};

	std::wstring VersionText(uint16_t major, uint16_t minor, uint16_t build, uint16_t qfe) {
		return std::to_wstring(major) + L"." + std::to_wstring(minor) + L"." + std::to_wstring(build) + L"." + std::to_wstring(qfe);
	}

	void WINAPI OnRundownEvent(PEVENT_RECORD record) {
		auto& context = *static_cast<RundownContext*>(record->UserContext);
		if (record->EventHeader.ProviderId != RundownProvider || record->EventHeader.ProcessId != context.Pid)
			return;
		if (DotNetInfo::ApplyRundownEvent(record->EventHeader.EventDescriptor.Id, record->EventHeader.EventDescriptor.Version,
			static_cast<uint8_t const*>(record->UserData), record->UserDataLength, context.Details, context.Completed))
			::SetEvent(context.hDone);
	}

	DWORD WINAPI RundownThread(void* param) {
		auto trace = *static_cast<PROCESSTRACE_HANDLE*>(param);
		return ::ProcessTrace(&trace, 1, nullptr, nullptr);
	}
}

bool DotNetInfo::ApplyRundownEvent(uint16_t eventId, uint8_t version, uint8_t const* data, size_t size, DotNetProcessDetails& details,
	std::vector<uint16_t>& completed) {
	PayloadReader r{ data, data + size };
	switch (eventId) {
		case RuntimeInformationDCStart:
		{
			DotNetRuntime rt;
			rt.ClrInstanceId = r.Get<uint16_t>();
			rt.Core = r.Get<uint16_t>() == 2;	// Sku: 1 the desktop CLR, 2 CoreCLR
			uint16_t v[8];
			for (auto& n : v)
				n = r.Get<uint16_t>();
			rt.BclVersion = VersionText(v[0], v[1], v[2], v[3]);
			rt.Version = VersionText(v[4], v[5], v[6], v[7]);
			rt.StartupFlags = r.Get<uint32_t>();
			r.Get<uint8_t>();	// StartupMode
			rt.CommandLine = r.String();
			r.Get<GUID>();	// ComObjectGuid
			rt.RuntimePath = r.String();
			if (r.Ok)
				details.Runtimes.push_back(std::move(rt));
			break;
		}
		case AppDomainDCStart:
		{
			DotNetAppDomain d;
			d.Id = r.Get<uint64_t>();
			d.Flags = r.Get<uint32_t>();
			d.Name = r.String();
			if (version >= 1)
				d.Index = r.Get<uint32_t>();
			if (r.Ok)
				details.AppDomains.push_back(std::move(d));
			break;
		}
		case AssemblyDCStart:
		{
			DotNetAssembly a;
			a.Id = r.Get<uint64_t>();
			a.AppDomainId = r.Get<uint64_t>();
			if (version >= 1)
				r.Get<uint64_t>();	// BindingID
			a.Flags = r.Get<uint32_t>();
			a.FullName = r.String();
			if (r.Ok)
				details.Assemblies.push_back(std::move(a));
			break;
		}
		case ModuleDCStart:
		{
			DotNetModule m;
			m.Id = r.Get<uint64_t>();
			m.AssemblyId = r.Get<uint64_t>();
			m.Flags = r.Get<uint32_t>();
			r.Get<uint32_t>();	// Reserved1
			m.ILPath = r.String();
			m.NativePath = r.String();
			if (r.Ok)
				details.Modules.push_back(std::move(m));
			break;
		}
		case DCStartComplete:
		{
			// version 0 has no payload: the only runtime
			auto instance = version >= 1 ? r.Get<uint16_t>() : (uint16_t)0;
			completed.push_back(instance);
			// done when every runtime that said it's there is (the runtime information comes first)
			bool all = version == 0 || std::all_of(details.Runtimes.begin(), details.Runtimes.end(), [&](auto& rt) {
				return std::find(completed.begin(), completed.end(), rt.ClrInstanceId) != completed.end();
				});
			if (all) {
				details.Complete = true;
				return true;
			}
			break;
		}
	}
	return false;
}

std::optional<DotNetProcessDetails> DotNetInfo::QueryProcess(uint32_t pid, PCWSTR sessionPrefix, uint32_t timeoutMs, HANDLE hCancel) {
	static LONG s_Sequence;
	std::wstring prefix(sessionPrefix);
	Etw::StopOrphanedSessions(prefix);
	// unique in the process, so that two queries can run at once ("<prefix><pid>" is what StopOrphanedSessions reads)
	auto name = prefix + std::to_wstring(::GetCurrentProcessId()) + L"." + std::to_wstring(::InterlockedIncrement(&s_Sequence));

	TRACEHANDLE session = 0;
	auto props = Etw::MakeProperties();
	auto error = ::StartTrace(&session, name.c_str(), &props.Properties);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return std::nullopt;
	}

	RundownContext context{ pid };
	wil::unique_handle hDone(::CreateEvent(nullptr, TRUE, FALSE, nullptr));
	context.hDone = hDone.get();

	// the consumer first, so that no event is lost
	EVENT_TRACE_LOGFILE log{};
	log.LoggerName = name.data();
	log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	log.EventRecordCallback = OnRundownEvent;
	log.Context = &context;
	PROCESSTRACE_HANDLE trace = ::OpenTrace(&log);
	wil::unique_handle hThread;
	if (trace == INVALID_PROCESSTRACE_HANDLE)
		error = ::GetLastError();
	else {
		hThread.reset(::CreateThread(nullptr, 0, RundownThread, &trace, 0, nullptr));
		if (!hThread)
			error = ::GetLastError();
	}

	if (error == ERROR_SUCCESS) {
		// only the process's runtime is told about the session, so only it runs down
		ULONG pids[] = { pid };
		EVENT_FILTER_DESCRIPTOR filter{};
		filter.Ptr = (ULONGLONG)pids;
		filter.Size = sizeof(pids);
		filter.Type = EVENT_FILTER_TYPE_PID;
		ENABLE_TRACE_PARAMETERS params{};
		params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
		params.EnableFilterDesc = &filter;
		params.FilterDescCount = 1;
		error = ::EnableTraceEx2(session, &RundownProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
			LoaderRundownKeyword | StartRundownKeyword, 0, 0, &params);
		if (error == ERROR_SUCCESS) {
			// the buffers flushed often, rather than every second (FlushTimer), as the rundown takes milliseconds
			HANDLE handles[] = { hDone.get(), hCancel };
			auto start = ::GetTickCount64();
			for (;;) {
				auto elapsed = ::GetTickCount64() - start;
				if (elapsed >= timeoutMs)
					break;
				auto wait = ::WaitForMultipleObjects(hCancel ? 2 : 1, handles, FALSE, (DWORD)std::min<uint64_t>(timeoutMs - elapsed, 250));
				if (wait != WAIT_TIMEOUT)
					break;
				auto flush = Etw::MakeProperties();
				::ControlTrace(session, nullptr, &flush.Properties, EVENT_TRACE_CONTROL_FLUSH);
			}
		}
	}

	// stopping the session delivers what's still in its buffers, then ProcessTrace returns
	auto stop = Etw::MakeProperties();
	::ControlTrace(session, nullptr, &stop.Properties, EVENT_TRACE_CONTROL_STOP);
	if (hThread && ::WaitForSingleObject(hThread.get(), 5000) == WAIT_TIMEOUT) {
		::CloseTrace(trace);
		::WaitForSingleObject(hThread.get(), INFINITE);
		trace = INVALID_PROCESSTRACE_HANDLE;
	}
	if (trace != INVALID_PROCESSTRACE_HANDLE)
		::CloseTrace(trace);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return std::nullopt;
	}
	return std::move(context.Details);
}

// --- the diagnostics IPC protocol (.NET Core and later)

namespace {
	// the header of every request and answer: the magic, the whole message's size, the command set and ID, reserved
#pragma pack(push, 1)
	struct IpcHeader {
		uint8_t Magic[14];	// "DOTNET_IPC_V1" and its NUL
		uint16_t Size;
		uint8_t CommandSet;
		uint8_t CommandId;
		uint16_t Reserved;
	};
#pragma pack(pop)
	static_assert(sizeof(IpcHeader) == 20);
	constexpr uint8_t ProcessCommandSet = 0x04, ServerCommandSet = 0xFF;
	constexpr uint8_t ProcessInfoCommand = 0x00, ProcessInfo2Command = 0x04, ServerOk = 0x00;

	// a strict read of the answer: an overlapped one, given up after the time left
	bool Transfer(HANDLE hPipe, bool write, void* buffer, DWORD size, uint64_t deadline) {
		auto bytes = static_cast<BYTE*>(buffer);
		DWORD done = 0;
		while (done < size) {
			wil::unique_event_nothrow event;
			if (!event.try_create(wil::EventOptions::ManualReset, nullptr))
				return false;
			OVERLAPPED ov{};
			ov.hEvent = event.get();
			DWORD transferred = 0;
			BOOL ok = write ? ::WriteFile(hPipe, bytes + done, size - done, nullptr, &ov) : ::ReadFile(hPipe, bytes + done, size - done, nullptr, &ov);
			if (!ok && ::GetLastError() != ERROR_IO_PENDING)
				return false;
			auto now = ::GetTickCount64();
			if (::WaitForSingleObject(event.get(), now >= deadline ? 0 : (DWORD)(deadline - now)) != WAIT_OBJECT_0) {
				::CancelIoEx(hPipe, &ov);
				::GetOverlappedResult(hPipe, &ov, &transferred, TRUE);
				::SetLastError(ERROR_TIMEOUT);
				return false;
			}
			if (!::GetOverlappedResult(hPipe, &ov, &transferred, FALSE) || transferred == 0)
				return false;
			done += transferred;
		}
		return true;
	}

	// one command on a new connection (the runtime answers one and closes it): the answer's payload, or nothing
	std::optional<std::vector<uint8_t>> IpcCommand(std::wstring const& pipe, uint8_t commandId, uint64_t deadline, bool& unknownCommand) {
		unknownCommand = false;
		wil::unique_hfile hPipe(::CreateFileW((L"\\\\.\\pipe\\" + pipe).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED, nullptr));
		if (!hPipe)
			return std::nullopt;
		IpcHeader request{};
		memcpy(request.Magic, "DOTNET_IPC_V1", 14);
		request.Size = sizeof(IpcHeader);
		request.CommandSet = ProcessCommandSet;
		request.CommandId = commandId;
		if (!Transfer(hPipe.get(), true, &request, sizeof(request), deadline))
			return std::nullopt;
		IpcHeader answer{};
		if (!Transfer(hPipe.get(), false, &answer, sizeof(answer), deadline))
			return std::nullopt;
		if (memcmp(answer.Magic, "DOTNET_IPC_V1", 14) != 0 || answer.Size < sizeof(IpcHeader) || answer.CommandSet != ServerCommandSet) {
			::SetLastError(ERROR_INVALID_DATA);
			return std::nullopt;
		}
		std::vector<uint8_t> payload(answer.Size - sizeof(IpcHeader));
		if (!payload.empty() && !Transfer(hPipe.get(), false, payload.data(), (DWORD)payload.size(), deadline))
			return std::nullopt;
		if (answer.CommandId != ServerOk) {
			// an error: its HRESULT (0x80131384, an unknown command: an older runtime)
			uint32_t hr = 0;
			if (payload.size() >= sizeof(hr))
				memcpy(&hr, payload.data(), sizeof(hr));
			unknownCommand = hr == 0x80131384;
			::SetLastError(ERROR_NOT_SUPPORTED);
			return std::nullopt;
		}
		return payload;
	}
}

std::wstring DotNetInfo::FindDiagnosticsPipe(uint32_t pid) {
	// "dotnet-diagnostic-<pid>" on Windows ("-<n>-socket" follows it only in the Unix socket's name); a suffix after a dash
	// is taken too, in case a runtime adds one
	auto name = L"dotnet-diagnostic-" + std::to_wstring(pid);
	WIN32_FIND_DATA fd;
	wil::unique_hfind hFind(::FindFirstFile(L"\\\\.\\pipe\\*", &fd));
	if (!hFind)
		return L"";
	do {
		std::wstring_view pipe(fd.cFileName);
		if (pipe == name || (pipe.starts_with(name) && pipe.size() > name.size() && pipe[name.size()] == L'-'))
			return fd.cFileName;
	} while (::FindNextFile(hFind.get(), &fd));
	return L"";
}

std::optional<DotNetCoreProcessInfo> DotNetInfo::ParseProcessInfo(uint8_t const* payload, size_t size, bool v2) {
	PayloadReader reader{ payload, payload + size };
	// strings: a count of characters with the NUL, then the characters
	auto string = [&]() -> std::wstring {
		auto count = reader.Get<uint32_t>();
		if (!reader.Ok || count == 0)
			return L"";
		if ((size_t)(reader.End - reader.Pos) < (size_t)count * sizeof(WCHAR)) {
			reader.Ok = false;
			reader.Pos = reader.End;
			return L"";
		}
		std::wstring text(reinterpret_cast<WCHAR const*>(reader.Pos), count);
		reader.Pos += (size_t)count * sizeof(WCHAR);
		text.resize(::wcsnlen(text.c_str(), text.size()));
		return text;
	};
	DotNetCoreProcessInfo info;
	info.ProcessId = reader.Get<uint64_t>();
	info.RuntimeCookie = reader.Get<GUID>();
	info.CommandLine = string();
	info.Os = string();
	info.Architecture = string();
	if (v2) {
		info.EntryAssembly = string();
		info.ClrVersion = string();
	}
	if (!reader.Ok)
		return std::nullopt;
	return info;
}

std::optional<DotNetCoreProcessInfo> DotNetInfo::QueryCoreProcessInfo(uint32_t pid, uint32_t timeoutMs) {
	auto pipe = FindDiagnosticsPipe(pid);
	if (pipe.empty()) {
		::SetLastError(ERROR_FILE_NOT_FOUND);
		return std::nullopt;
	}
	auto deadline = ::GetTickCount64() + timeoutMs;
	bool unknown = false;
	if (auto payload = IpcCommand(pipe, ProcessInfo2Command, deadline, unknown))
		return ParseProcessInfo(payload->data(), payload->size(), true);
	// a runtime before .NET 6 knows only ProcessInfo
	if (!unknown)
		return std::nullopt;
	if (auto payload = IpcCommand(pipe, ProcessInfoCommand, deadline, unknown))
		return ParseProcessInfo(payload->data(), payload->size(), false);
	return std::nullopt;
}

// --- garbage collections, from ETW

namespace {
	// Microsoft-Windows-DotNETRuntime
	const GUID RuntimeProvider = { 0xE13C0D23, 0xCCBC, 0x4E12, { 0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4 } };
	const ULONGLONG GcKeyword = 0x1;
	enum GcEvent : USHORT { GCStart = 1, GCRestartEEEnd = 3, GCHeapStats = 4, GCSuspendEEBegin = 9 };
}

uint64_t DotNetGcStats::HeapSize() const {
	return GenerationSize[0] + GenerationSize[1] + GenerationSize[2] + LohSize + PohSize;
}

bool DotNetGcMonitor::ApplyGcEvent(uint16_t eventId, uint8_t version, uint8_t const* data, size_t size, int64_t timeStamp, DotNetGcStats& stats) {
	PayloadReader reader{ data, data + size };
	switch (eventId) {
		case GCStart: {
			// V1 and later: Count, Depth, Reason, Type, ClrInstanceID (V2 adds the client sequence number)
			if (version < 1)
				return false;
			reader.Get<uint32_t>();
			auto depth = reader.Get<uint32_t>();
			auto reason = reader.Get<uint32_t>();
			if (!reader.Ok)
				return false;
			stats.Collections++;
			if (depth < 3)
				stats.ByGeneration[depth]++;
			stats.LastGeneration = depth;
			stats.LastReason = reason;
			return true;
		}
		case GCHeapStats: {
			// the generations' sizes and promoted sizes (0..3, 3 the large object heap), finalization, pinned objects,
			// sink blocks, GC handles, ClrInstanceID; V2 adds the pinned object heap's (4)
			uint64_t sizes[4];
			for (int g = 0; g < 4; g++) {
				sizes[g] = reader.Get<uint64_t>();
				reader.Get<uint64_t>();
			}
			reader.Get<uint64_t>();
			reader.Get<uint64_t>();
			auto pinned = reader.Get<uint32_t>();
			reader.Get<uint32_t>();
			auto handles = reader.Get<uint32_t>();
			reader.Get<uint16_t>();
			if (!reader.Ok)
				return false;
			uint64_t poh = 0;
			if (version >= 2) {
				poh = reader.Get<uint64_t>();
				if (!reader.Ok)
					poh = 0;
			}
			stats.HasHeap = true;
			for (int g = 0; g < 3; g++)
				stats.GenerationSize[g] = sizes[g];
			stats.LohSize = sizes[3];
			stats.PohSize = poh;
			stats.PinnedObjects = pinned;
			stats.GcHandles = handles;
			return true;
		}
		case GCSuspendEEBegin:
			stats.SuspendStart = timeStamp;
			return true;
		case GCRestartEEEnd:
			if (stats.SuspendStart == 0 || timeStamp < stats.SuspendStart)
				return false;
			stats.LastPause = (uint64_t)(timeStamp - stats.SuspendStart);
			stats.MaxPause = (std::max)(stats.MaxPause, stats.LastPause);
			stats.TotalPause += stats.LastPause;
			stats.SuspendStart = 0;
			return true;
	}
	return false;
}

struct DotNetGcMonitor::State {
	uint32_t Pid{ 0 };
	TRACEHANDLE Session{ 0 };
	PROCESSTRACE_HANDLE Trace{ INVALID_PROCESSTRACE_HANDLE };
	wil::unique_handle Thread;
	std::wstring Name;
	mutable SRWLOCK Lock = SRWLOCK_INIT;
	DotNetGcStats Stats;
};

namespace {
	void WINAPI OnGcEvent(PEVENT_RECORD record) {
		auto& state = *static_cast<DotNetGcMonitor::State*>(record->UserContext);
		if (record->EventHeader.ProviderId != RuntimeProvider || record->EventHeader.ProcessId != state.Pid)
			return;
		::AcquireSRWLockExclusive(&state.Lock);
		DotNetGcMonitor::ApplyGcEvent(record->EventHeader.EventDescriptor.Id, record->EventHeader.EventDescriptor.Version,
			static_cast<uint8_t const*>(record->UserData), record->UserDataLength, record->EventHeader.TimeStamp.QuadPart, state.Stats);
		::ReleaseSRWLockExclusive(&state.Lock);
	}

	DWORD WINAPI GcThread(void* param) {
		auto trace = static_cast<DotNetGcMonitor::State*>(param)->Trace;
		return ::ProcessTrace(&trace, 1, nullptr, nullptr);
	}
}

DotNetGcMonitor::~DotNetGcMonitor() {
	Stop();
}

bool DotNetGcMonitor::Start(uint32_t pid, PCWSTR sessionPrefix) {
	Stop();
	static LONG s_Sequence;
	std::wstring prefix(sessionPrefix);
	Etw::StopOrphanedSessions(prefix);
	auto state = new State;
	state->Pid = pid;
	state->Name = prefix + std::to_wstring(::GetCurrentProcessId()) + L"." + std::to_wstring(::InterlockedIncrement(&s_Sequence));
	auto props = Etw::MakeProperties();
	auto error = ::StartTrace(&state->Session, state->Name.c_str(), &props.Properties);
	if (error != ERROR_SUCCESS) {
		delete state;
		::SetLastError(error);
		return false;
	}
	m_State = state;
	// the consumer first, so that no event is lost
	EVENT_TRACE_LOGFILE log{};
	log.LoggerName = state->Name.data();
	log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	log.EventRecordCallback = OnGcEvent;
	log.Context = state;
	state->Trace = ::OpenTrace(&log);
	if (state->Trace == INVALID_PROCESSTRACE_HANDLE)
		error = ::GetLastError();
	else {
		state->Thread.reset(::CreateThread(nullptr, 0, GcThread, state, 0, nullptr));
		if (!state->Thread)
			error = ::GetLastError();
	}
	if (error == ERROR_SUCCESS) {
		ULONG pids[] = { pid };
		EVENT_FILTER_DESCRIPTOR filter{};
		filter.Ptr = (ULONGLONG)pids;
		filter.Size = sizeof(pids);
		filter.Type = EVENT_FILTER_TYPE_PID;
		ENABLE_TRACE_PARAMETERS params{};
		params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
		params.EnableFilterDesc = &filter;
		params.FilterDescCount = 1;
		error = ::EnableTraceEx2(state->Session, &RuntimeProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
			GcKeyword, 0, 0, &params);
	}
	if (error != ERROR_SUCCESS) {
		Stop();
		::SetLastError(error);
		return false;
	}
	return true;
}

void DotNetGcMonitor::Stop() {
	if (!m_State)
		return;
	auto state = m_State;
	m_State = nullptr;
	// stopping the session delivers what's still in its buffers, then ProcessTrace returns
	auto stop = Etw::MakeProperties();
	::ControlTrace(state->Session, nullptr, &stop.Properties, EVENT_TRACE_CONTROL_STOP);
	if (state->Thread && ::WaitForSingleObject(state->Thread.get(), 5000) == WAIT_TIMEOUT) {
		::CloseTrace(state->Trace);
		::WaitForSingleObject(state->Thread.get(), INFINITE);
		state->Trace = INVALID_PROCESSTRACE_HANDLE;
	}
	if (state->Trace != INVALID_PROCESSTRACE_HANDLE)
		::CloseTrace(state->Trace);
	delete state;
}

bool DotNetGcMonitor::IsRunning() const {
	return m_State != nullptr;
}

DotNetGcStats DotNetGcMonitor::GetStats() const {
	if (!m_State)
		return {};
	::AcquireSRWLockShared(&m_State->Lock);
	auto stats = m_State->Stats;
	::ReleaseSRWLockShared(&m_State->Lock);
	return stats;
}

void DotNetGcMonitor::Flush() {
	if (!m_State)
		return;
	auto flush = Etw::MakeProperties();
	::ControlTrace(m_State->Session, nullptr, &flush.Properties, EVENT_TRACE_CONTROL_FLUSH);
}
