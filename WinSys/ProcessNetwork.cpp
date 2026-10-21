#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include "ProcessNetwork.h"

using namespace WinSys;

namespace {
	// Microsoft-Windows-Kernel-Network
	const GUID KernelNetworkProvider = { 0x7dd42a49, 0x5329, 0x4832, { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 } };
	const ULONGLONG KeywordIPv4 = 0x10, KeywordIPv6 = 0x20;

	// the TCP and UDP send and receive events; each starts with the process ID and the size (both UInt32)
	enum class Direction { None, Send, Receive };
	Direction GetDirection(USHORT id) {
		switch (id) {
			case 10: case 26: case 42: case 58: return Direction::Send;		// TCP IPv4, TCP IPv6, UDP IPv4, UDP IPv6
			case 11: case 27: case 43: case 59: return Direction::Receive;
		}
		return Direction::None;
	}

	struct SessionProperties {
		EVENT_TRACE_PROPERTIES Properties;
		WCHAR Name[1024];
	};

	SessionProperties MakeProperties() {
		SessionProperties props{};
		props.Properties.Wnode.BufferSize = sizeof(props);
		props.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		props.Properties.Wnode.ClientContext = 1;	// QueryPerformanceCounter time stamps
		props.Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		props.Properties.FlushTimer = 1;	// seconds
		props.Properties.LoggerNameOffset = offsetof(SessionProperties, Name);
		return props;
	}

	// stops "<prefix> <pid>" sessions whose process is gone
	void StopOrphanedSessions(std::wstring const& prefix) {
		std::vector<SessionProperties> sessions(64);	// the most sessions the system allows
		std::vector<EVENT_TRACE_PROPERTIES*> pointers;
		for (auto& s : sessions) {
			s = MakeProperties();
			pointers.push_back(&s.Properties);
		}
		ULONG count = 0;
		if (::QueryAllTraces(pointers.data(), (ULONG)pointers.size(), &count) != ERROR_SUCCESS)
			return;
		for (ULONG i = 0; i < count; i++) {
			std::wstring_view name(sessions[i].Name);
			if (!name.starts_with(prefix))
				continue;
			auto pid = (DWORD)::_wtoi(name.data() + prefix.size());
			wil::unique_handle hProcess(::OpenProcess(SYNCHRONIZE, FALSE, pid));
			if (pid == 0 || (!hProcess && ::GetLastError() == ERROR_INVALID_PARAMETER)
				|| (hProcess && ::WaitForSingleObject(hProcess.get(), 0) == WAIT_OBJECT_0)) {
				auto stop = MakeProperties();
				::ControlTrace(0, sessions[i].Name, &stop.Properties, EVENT_TRACE_CONTROL_STOP);
			}
		}
	}
}

ProcessNetworkTracker::~ProcessNetworkTracker() {
	Stop();
}

bool ProcessNetworkTracker::Start(PCWSTR sessionPrefix) {
	if (IsRunning())
		return true;

	std::wstring prefix = std::wstring(sessionPrefix) + L" ";
	StopOrphanedSessions(prefix);
	m_SessionName = prefix + std::to_wstring(::GetCurrentProcessId());
	auto props = MakeProperties();
	TRACEHANDLE session;
	auto error = ::StartTrace(&session, m_SessionName.c_str(), &props.Properties);
	if (error == ERROR_ALREADY_EXISTS) {
		// this process's, from a tracker that wasn't stopped
		auto stop = MakeProperties();
		::ControlTrace(0, m_SessionName.c_str(), &stop.Properties, EVENT_TRACE_CONTROL_STOP);
		props = MakeProperties();
		error = ::StartTrace(&session, m_SessionName.c_str(), &props.Properties);
	}
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return false;
	}
	m_Session = session;

	error = ::EnableTraceEx2(session, &KernelNetworkProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
		KeywordIPv4 | KeywordIPv6, 0, 0, nullptr);
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

void ProcessNetworkTracker::Stop() {
	if (m_Session) {
		auto props = MakeProperties();
		::ControlTrace(m_Session, nullptr, &props.Properties, EVENT_TRACE_CONTROL_STOP);
		m_Session = 0;
	}
	if (m_Trace) {
		// ProcessTrace returns once the trace is closed
		::CloseTrace(m_Trace);
		m_Trace = 0;
	}
	if (m_hThread) {
		::WaitForSingleObject(m_hThread.get(), INFINITE);
		m_hThread.reset();
	}
	auto lock = m_Lock.lock_exclusive();
	m_Counters.clear();
	m_Connections.clear();
}

bool ProcessNetworkTracker::IsRunning() const {
	return m_Session != 0;
}

ProcessNetworkTracker::Counters ProcessNetworkTracker::GetCounters(uint32_t pid) const {
	auto lock = m_Lock.lock_shared();
	auto it = m_Counters.find(pid);
	return it == m_Counters.end() ? Counters{} : it->second;
}

void ProcessNetworkTracker::RemoveProcess(uint32_t pid) {
	auto lock = m_Lock.lock_exclusive();
	m_Counters.erase(pid);
	std::erase_if(m_Connections, [&](auto const& c) { return c.first.Pid == pid; });
}

size_t ProcessNetworkTracker::ConnectionIdHash::operator()(ConnectionId const& id) const noexcept {
	// FNV-1a over the fields
	size_t hash = 14695981039346656037ull;
	auto add = [&](void const* data, size_t size) {
		for (size_t i = 0; i < size; i++)
			hash = (hash ^ static_cast<uint8_t const*>(data)[i]) * 1099511628211ull;
	};
	add(&id.Pid, sizeof(id.Pid));
	uint8_t flags = (id.Udp ? 1 : 0) | (id.V6 ? 2 : 0);
	add(&flags, 1);
	add(id.LocalAddress.data(), id.LocalAddress.size());
	add(id.RemoteAddress.data(), id.RemoteAddress.size());
	add(&id.LocalPort, sizeof(id.LocalPort));
	add(&id.RemotePort, sizeof(id.RemotePort));
	return hash;
}

ProcessNetworkTracker::Counters ProcessNetworkTracker::GetConnectionCounters(ConnectionId const& id) const {
	auto lock = m_Lock.lock_shared();
	auto it = m_Connections.find(id);
	return it == m_Connections.end() ? Counters{} : it->second;
}

void ProcessNetworkTracker::RetainConnections(std::vector<ConnectionId> const& live) {
	std::unordered_map<ConnectionId, Counters, ConnectionIdHash> kept;
	auto lock = m_Lock.lock_exclusive();
	kept.reserve(live.size());
	for (auto& id : live)
		if (auto it = m_Connections.find(id); it != m_Connections.end())
			kept.insert(*it);
	m_Connections.swap(kept);
}

DWORD WINAPI ProcessNetworkTracker::ProcessThread(void* param) {
	auto tracker = static_cast<ProcessNetworkTracker*>(param);
	PROCESSTRACE_HANDLE trace = tracker->m_Trace;
	return ::ProcessTrace(&trace, 1, nullptr, nullptr);
}

void WINAPI ProcessNetworkTracker::OnEvent(PEVENT_RECORD record) {
	if (record->EventHeader.ProviderId != KernelNetworkProvider || record->UserDataLength < 2 * sizeof(uint32_t))
		return;
	auto direction = GetDirection(record->EventHeader.EventDescriptor.Id);
	if (direction == Direction::None)
		return;

	// the header's process ID is whatever process the event was raised in (often System for a receive); the payload's is the owner
	auto data = static_cast<uint32_t const*>(record->UserData);
	uint32_t pid = data[0], size = data[1];

	// then daddr, saddr (4 or 16 bytes), dport, sport (network order): d is the remote end, s the local one, in sends
	// and receives alike
	auto id = record->EventHeader.EventDescriptor.Id;
	ConnectionId connection;
	connection.Pid = pid;
	connection.V6 = id == 26 || id == 27 || id == 58 || id == 59;
	connection.Udp = id >= 42;
	size_t length = connection.V6 ? 16 : 4;
	bool hasEnds = record->UserDataLength >= 2 * sizeof(uint32_t) + 2 * length + 2 * sizeof(uint16_t);
	if (hasEnds) {
		auto ends = static_cast<uint8_t const*>(record->UserData) + 2 * sizeof(uint32_t);
		uint16_t remotePort, localPort;
		memcpy(&remotePort, ends + 2 * length, sizeof(remotePort));
		memcpy(&localPort, ends + 2 * length + sizeof(remotePort), sizeof(localPort));
		connection.LocalPort = _byteswap_ushort(localPort);
		if (!connection.Udp) {
			memcpy(connection.RemoteAddress.data(), ends, length);
			memcpy(connection.LocalAddress.data(), ends + length, length);
			connection.RemotePort = _byteswap_ushort(remotePort);
		}
	}

	auto tracker = static_cast<ProcessNetworkTracker*>(record->UserContext);
	auto lock = tracker->m_Lock.lock_exclusive();
	auto& counters = tracker->m_Counters[pid];
	(direction == Direction::Send ? counters.Sent : counters.Received) += size;
	if (hasEnds) {
		auto& c = tracker->m_Connections[connection];
		(direction == Direction::Send ? c.Sent : c.Received) += size;
	}
}
