#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include "ProcessCreation.h"
#include "EtwSession.h"
#include "ServiceManager.h"

using namespace WinSys;

namespace {
	// Microsoft-Windows-Kernel-Process
	const GUID KernelProcessProvider = { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };
	const ULONGLONG ProcessKeyword = 0x10;	// WINEVENT_KEYWORD_PROCESS
	const uint16_t ProcessStartId = 1;

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

std::vector<ProcessCreation> ProcessCreationTracker::GetMismatches() const {
	std::vector<ProcessCreation> result;
	auto lock = m_Lock.lock_shared();
	for (auto& [key, c] : m_Creations)
		if (c.Creator != ProcessCreator::Parent)
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
	auto tracker = static_cast<ProcessCreationTracker*>(record->UserContext);
	auto lock = tracker->m_Lock.lock_exclusive();
	tracker->m_Creations[c->Key()] = std::move(*c);
}
