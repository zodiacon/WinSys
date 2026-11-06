#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include "ProcessCreation.h"
#include "EtwSession.h"
#include "ServiceManager.h"

#pragma comment(lib, "tdh")

using namespace WinSys;

namespace {
	// Microsoft-Windows-Kernel-Process
	const GUID KernelProcessProvider = { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };
	const ULONGLONG ProcessKeyword = 0x10;	// WINEVENT_KEYWORD_PROCESS
	const uint16_t ProcessStartId = 1, ProcessStopId = 2;

	// an event's property by name (TDH: the layouts differ between versions); false if it has none
	bool GetProperty(PEVENT_RECORD record, PCWSTR name, std::vector<BYTE>& value) {
		PROPERTY_DATA_DESCRIPTOR descriptor{ (ULONGLONG)name, ULONG_MAX };
		ULONG size = 0;
		if (::TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0)
			return false;
		value.resize(size);
		return ::TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, value.data()) == ERROR_SUCCESS;
	}

	template<typename T>
	std::optional<T> GetValue(PEVENT_RECORD record, PCWSTR name) {
		std::vector<BYTE> value;
		if (!GetProperty(record, name, value) || value.size() < sizeof(T))
			return {};
		T result;
		memcpy(&result, value.data(), sizeof(T));
		return result;
	}

	// a UnicodeString's or an AnsiString's text
	std::wstring GetText(PEVENT_RECORD record, PCWSTR name, bool ansi) {
		std::vector<BYTE> value;
		if (!GetProperty(record, name, value))
			return L"";
		if (ansi) {
			std::string text((char const*)value.data(), strnlen((char const*)value.data(), value.size()));
			return std::wstring(text.begin(), text.end());
		}
		return std::wstring((PCWSTR)value.data(), wcsnlen((PCWSTR)value.data(), value.size() / sizeof(WCHAR)));
	}

	// the services that create processes for someone else: elevations and Run As
	const PCWSTR OnBehalfServices[] = { L"Appinfo", L"seclogon" };

	std::wstring ImageName(uint32_t pid) {
		wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
		if (!hProcess)
			return L"";
		WCHAR path[MAX_PATH];
		DWORD size = _countof(path);
		if (!::QueryFullProcessImageName(hProcess.get(), 0, path, &size))
			return L"";
		auto file = ::wcsrchr(path, L'\\');
		return file ? file + 1 : path;
	}

	// the on-behalf service the process hosts, if any
	std::wstring OnBehalfService(uint32_t pid) {
		for (auto name : OnBehalfServices) {
			auto status = ServiceManager::GetServiceStatus(name);
			if (status.ProcessId == pid && pid != 0)
				return name;
		}
		return L"";
	}
}

std::optional<ProcessCreation> ProcessCreationParser::Parse(uint16_t id, uint8_t version, void const* data, size_t size) {
	// version 3 has each process's sequence number (UInt64) after its ID
	size_t sequence = version >= 3 ? 8 : 0;
	if (id != ProcessStartId || !data || size < 16 + sequence)
		return {};
	auto p = (BYTE const*)data;
	ProcessCreation c;
	memcpy(&c.Pid, p, 4);
	memcpy(&c.CreateTime, p + 4 + sequence, 8);
	memcpy(&c.ParentPid, p + 12 + sequence, 4);
	return c;
}

ProcessCreator ProcessCreationParser::Classify(uint32_t creatorPid, uint32_t parentPid, std::wstring const& creatorService) {
	if (creatorPid == parentPid)
		return ProcessCreator::Parent;
	for (auto name : OnBehalfServices)
		if (::_wcsicmp(creatorService.c_str(), name) == 0)
			return ProcessCreator::OnBehalf;
	return ProcessCreator::Other;
}

std::wstring ProcessCreationParser::Describe(ProcessCreation const& c) {
	if (c.Creator == ProcessCreator::Parent)
		return L"";
	auto creator = (c.CreatorName.empty() ? std::wstring(L"process ") + std::to_wstring(c.CreatorPid)
		: c.CreatorName + L" (" + std::to_wstring(c.CreatorPid) + L")");
	if (c.Creator == ProcessCreator::OnBehalf)
		return L"Created by " + creator + L", the " + c.CreatorService + L" service, for its parent";
	return L"Parent spoofed: created by " + creator + L", not its parent (" + std::to_wstring(c.ParentPid) + L")";
}

//
// ProcessCreationTracker
//

ProcessCreationTracker::~ProcessCreationTracker() {
	Stop();
}

bool ProcessCreationTracker::Start(PCWSTR sessionPrefix) {
	if (IsRunning())
		return true;
	TRACEHANDLE session;
	auto error = Etw::StartSession(std::wstring(sessionPrefix) + L" ", m_SessionName, session);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return false;
	}
	m_Session = session;
	::GetSystemTimeAsFileTime((FILETIME*)&m_StartTime);
	error = ::EnableTraceEx2(session, &KernelProcessProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
		ProcessKeyword, 0, 0, nullptr);
	if (error == ERROR_SUCCESS) {
		EVENT_TRACE_LOGFILE log{};
		log.LoggerName = m_SessionName.data();
		log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
		log.EventRecordCallback = OnEvent;
		log.Context = this;
		auto trace = ::OpenTrace(&log);
		if (trace == INVALID_PROCESSTRACE_HANDLE)
			error = ::GetLastError();
		else {
			m_Trace = trace;
			m_hThread.reset(::CreateThread(nullptr, 0, ProcessThread, this, 0, nullptr));
			if (!m_hThread)
				error = ::GetLastError();
		}
	}
	if (error != ERROR_SUCCESS) {
		Stop();
		::SetLastError(error);
		return false;
	}
	return true;
}

void ProcessCreationTracker::Stop() {
	if (m_Session) {
		auto props = Etw::MakeProperties();
		::ControlTrace(m_Session, nullptr, &props.Properties, EVENT_TRACE_CONTROL_STOP);
		m_Session = 0;
	}
	if (m_Trace) {
		// ProcessTrace returns once the trace is closed
		::CloseTrace(m_Trace);
		m_Trace = 0;
	}
	if (m_hThread)
		::WaitForSingleObject(m_hThread.get(), INFINITE);
	m_hThread.reset();
	auto lock = m_Lock.lock_exclusive();
	m_Creations.clear();
	m_StartTime = 0;
}

bool ProcessCreationTracker::IsRunning() const {
	return m_Session != 0;
}

int64_t ProcessCreationTracker::GetStartTime() const {
	return m_StartTime;
}

std::optional<ProcessCreation> ProcessCreationTracker::Get(ProcessOrThreadKey const& key) const {
	auto lock = m_Lock.lock_shared();
	auto it = m_Creations.find(key);
	if (it == m_Creations.end())
		return {};
	return it->second;
}

std::vector<ProcessCreation> ProcessCreationTracker::TakeExited() {
	std::vector<ProcessCreation> result;
	int64_t now;
	::GetSystemTimeAsFileTime((FILETIME*)&now);
	auto lock = m_Lock.lock_exclusive();
	for (auto it = m_Creations.begin(); it != m_Creations.end();) {
		auto& c = it->second;
		if (c.ExitTime && !c.Taken && c.Started) {
			c.Taken = true;
			result.push_back(c);
		}
		// kept a while after their exit, for Get
		if (c.ExitTime && now - c.ExitTime > ExitedKept)
			it = m_Creations.erase(it);
		else
			++it;
	}
	return result;
}

std::vector<ProcessCreation> ProcessCreationTracker::GetMismatches() const {
	std::vector<ProcessCreation> result;
	auto lock = m_Lock.lock_shared();
	for (auto& [key, c] : m_Creations)
		if (c.Creator != ProcessCreator::Parent && !c.ExitTime)
			result.push_back(c);
	return result;
}

void ProcessCreationTracker::Remove(ProcessOrThreadKey const& key) {
	auto lock = m_Lock.lock_exclusive();
	m_Creations.erase(key);
}

DWORD WINAPI ProcessCreationTracker::ProcessThread(void* param) {
	auto tracker = static_cast<ProcessCreationTracker*>(param);
	PROCESSTRACE_HANDLE trace = tracker->m_Trace;
	return ::ProcessTrace(&trace, 1, nullptr, nullptr);
}

void WINAPI ProcessCreationTracker::OnEvent(PEVENT_RECORD record) {
	auto& header = record->EventHeader;
	if (header.ProviderId != KernelProcessProvider)
		return;
	auto tracker = static_cast<ProcessCreationTracker*>(record->UserContext);
	if (header.EventDescriptor.Id == ProcessStopId) {
		auto pid = GetValue<uint32_t>(record, L"ProcessID");
		auto created = GetValue<int64_t>(record, L"CreateTime");
		auto exited = GetValue<int64_t>(record, L"ExitTime");
		if (!pid || !created || !exited)
			return;
		auto code = GetValue<uint32_t>(record, L"ExitCode");
		auto name = GetText(record, L"ImageName", true);
		auto lock = tracker->m_Lock.lock_exclusive();
		auto& c = tracker->m_Creations[{ *created, *pid }];
		c.Pid = *pid;
		c.CreateTime = *created;
		c.ExitTime = *exited;
		c.ExitCode = code;
		if (c.ImagePath.empty())
			c.ImagePath = name;
		return;
	}
	auto c = ProcessCreationParser::Parse(header.EventDescriptor.Id, header.EventDescriptor.Version, record->UserData, record->UserDataLength);
	if (!c)
		return;
	// logged in the creating thread's context
	c->CreatorPid = header.ProcessId;
	c->CreatorTid = header.ThreadId;
	if (c->CreatorPid != c->ParentPid) {
		// rare: the creator is still running (it's creating), so it can be asked now
		c->CreatorService = OnBehalfService(c->CreatorPid);
		c->CreatorName = ImageName(c->CreatorPid);
	}
	c->Creator = ProcessCreationParser::Classify(c->CreatorPid, c->ParentPid, c->CreatorService);
	c->ImagePath = GetText(record, L"ImageName", false);
	c->Started = true;
	auto lock = tracker->m_Lock.lock_exclusive();
	// a stop can't come first: the start's fields go in a record that may have its stop already (a very short process)
	auto& existing = tracker->m_Creations[c->Key()];
	c->ExitTime = existing.ExitTime;
	c->ExitCode = existing.ExitCode;
	existing = std::move(*c);
}
