#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include "Ipc.h"
#include "EtwSession.h"

using namespace WinSys;

namespace {
	// the system ALPC provider (SystemAlpcProviderGuid, SYSTEM_ALPC_KW_GENERAL), enabled on a system logger session;
	// its events come as the kernel's classic ALPC events, by their class's GUID
	const GUID SystemAlpcProvider = { 0xfcb9baaf, 0xe529, 0x4980, { 0x92, 0xe9, 0xce, 0xd1, 0xa6, 0xaa, 0xdf, 0xdf } };
	const ULONGLONG SystemAlpcKeywordGeneral = 0x1;
	const GUID AlpcEventClass = { 0x45d8cccd, 0x539f, 0x4b72, { 0xa8, 0xb7, 0x5c, 0x68, 0x31, 0x42, 0x60, 0x9a } };
	enum AlpcOpcode : UCHAR { AlpcSend = 33, AlpcReceive = 34, AlpcWaitForReply = 35 };

	// Microsoft-Windows-RPC: client call start (5) and server call start (6), whose data is the interface (GUID), the
	// procedure number and the protocol (UInt32), then the network address, the endpoint and the options (strings)
	const GUID RpcProvider = { 0x6ad52b32, 0xd609, 0x4be9, { 0xae, 0x07, 0xce, 0x8d, 0xae, 0x93, 0x7e, 0x39 } };
	enum RpcEvent : USHORT { ClientCallStart = 5, ServerCallStart = 6 };

	// an ALPC message ID is reused once the message is done with: one this old starts over
	const uint64_t PendingLifetime = 10000;	// ms

	int64_t Now() {
		int64_t now;
		::GetSystemTimeAsFileTime(reinterpret_cast<FILETIME*>(&now));
		return now;
	}
}

IpcTracker::~IpcTracker() {
	Stop();
}

bool IpcTracker::Start(PCWSTR sessionPrefix) {
	if (IsRunning())
		return true;

	TRACEHANDLE session;
	auto error = Etw::StartSession(std::wstring(sessionPrefix) + L" ", m_SessionName, session, EVENT_TRACE_SYSTEM_LOGGER_MODE);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return false;
	}
	m_Session = session;

	error = ::EnableTraceEx2(session, &SystemAlpcProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
		SystemAlpcKeywordGeneral, 0, 0, nullptr);
	if (error == ERROR_SUCCESS)
		// the call start events are at the information level; the packets', which aren't wanted, are verbose
		error = ::EnableTraceEx2(session, &RpcProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
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
	m_StartTime = Now();
	return true;
}

void IpcTracker::Stop() {
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
	if (m_hThread) {
		::WaitForSingleObject(m_hThread.get(), INFINITE);
		m_hThread.reset();
	}
	m_Pending.clear();
	auto lock = m_Lock.lock_exclusive();
	m_Alpc.clear();
	m_Rpc.clear();
	m_Endpoints.clear();
	m_StartTime = 0;
}

bool IpcTracker::IsRunning() const {
	return m_Session != 0;
}

int64_t IpcTracker::GetStartTime() const {
	return m_StartTime;
}

PCWSTR IpcTracker::ProtocolName(RpcProtocol protocol) {
	switch (protocol) {
		case RpcProtocol::Tcp: return L"TCP";
		case RpcProtocol::NamedPipe: return L"Named Pipe";
		case RpcProtocol::Lrpc: return L"LRPC";
		case RpcProtocol::Http: return L"HTTP";
	}
	return L"";
}

std::wstring IpcTracker::GetInterfaceName(GUID const& iface) {
	// the documented protocols' interfaces ([MS-SCMR], [MS-LSAD], [MS-SAMR]...)
	static const struct {
		GUID Interface;
		PCWSTR Name;
	} known[] = {
		{ { 0xe1af8308, 0x5d1f, 0x11c9, { 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa } }, L"Endpoint Mapper (epmapper)" },
		{ { 0x367abb81, 0x9844, 0x35f1, { 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 } }, L"Service Control Manager (svcctl)" },
		{ { 0x12345778, 0x1234, 0xabcd, { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab } }, L"LSA (lsarpc)" },
		{ { 0x12345778, 0x1234, 0xabcd, { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac } }, L"SAM (samr)" },
		{ { 0x12345678, 0x1234, 0xabcd, { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb } }, L"Netlogon" },
		{ { 0x12345678, 0x1234, 0xabcd, { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab } }, L"Print Spooler (spoolss)" },
		{ { 0x338cd001, 0x2244, 0x31f1, { 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03 } }, L"Remote Registry (winreg)" },
		{ { 0x4b324fc8, 0x1670, 0x01d3, { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 } }, L"Server Service (srvsvc)" },
		{ { 0x6bffd098, 0xa112, 0x3610, { 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a } }, L"Workstation Service (wkssvc)" },
		{ { 0x86d35949, 0x83c9, 0x4044, { 0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c } }, L"Task Scheduler (ITaskSchedulerService)" },
		{ { 0x82273fdc, 0xe32a, 0x18c3, { 0x3f, 0x78, 0x82, 0x79, 0x29, 0xdc, 0x23, 0xea } }, L"Event Log (eventlog)" },
		{ { 0xf6beaff7, 0x1e19, 0x4fbb, { 0x9f, 0x8f, 0xb8, 0x9e, 0x20, 0x18, 0x33, 0x7c } }, L"Event Log (even6)" },
		{ { 0x99fcfec4, 0x5260, 0x101b, { 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a } }, L"DCOM OXID Resolver (IObjectExporter)" },
		{ { 0x000001a0, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } }, L"DCOM Activation (IRemoteSCMActivator)" },
		{ { 0x4d9f4ab8, 0x7d1c, 0x11cf, { 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57 } }, L"DCOM Activation (IActivation)" },
	};
	for (auto& k : known)
		if (::IsEqualGUID(k.Interface, iface))
			return k.Name;

	WCHAR text[64];
	if (!::StringFromGUID2(iface, text, _countof(text)))
		return L"";
	std::wstring key = std::wstring(L"Interface\\") + text;
	WCHAR name[256];
	DWORD size = sizeof(name);
	if (::RegGetValue(HKEY_CLASSES_ROOT, key.c_str(), nullptr, RRF_RT_REG_SZ, nullptr, name, &size) == ERROR_SUCCESS)
		return name;
	return L"";
}

std::wstring IpcTracker::EndpointKey(RpcProtocol protocol, std::wstring const& endpoint) {
	return std::to_wstring((uint32_t)protocol) + L":" + endpoint;
}

void IpcTracker::Counter::Add(int64_t now) {
	if (Count++ == 0)
		FirstSeen = now;
	LastSeen = now;
}

bool IpcTracker::RpcKey::operator==(RpcKey const& other) const {
	return ClientPid == other.ClientPid && ::IsEqualGUID(Interface, other.Interface) && Protocol == other.Protocol
		&& Endpoint == other.Endpoint && NetworkAddress == other.NetworkAddress;
}

size_t IpcTracker::RpcKeyHash::operator()(RpcKey const& key) const noexcept {
	// FNV-1a over the fixed fields, then the strings' hashes mixed in
	size_t hash = 14695981039346656037ull;
	auto add = [&](void const* data, size_t size) {
		for (size_t i = 0; i < size; i++)
			hash = (hash ^ static_cast<uint8_t const*>(data)[i]) * 1099511628211ull;
	};
	add(&key.ClientPid, sizeof(key.ClientPid));
	add(&key.Interface, sizeof(key.Interface));
	add(&key.Protocol, sizeof(key.Protocol));
	auto endpoint = std::hash<std::wstring>()(key.Endpoint), address = std::hash<std::wstring>()(key.NetworkAddress);
	add(&endpoint, sizeof(endpoint));
	add(&address, sizeof(address));
	return hash;
}

std::vector<IpcLink> IpcTracker::GetLinks() const {
	std::vector<IpcLink> links;
	auto lock = m_Lock.lock_shared();
	links.reserve(m_Alpc.size() + m_Rpc.size());
	for (auto& [pair, counter] : m_Alpc) {
		IpcLink link;
		link.Kind = IpcKind::Alpc;
		link.ClientPid = (uint32_t)(pair >> 32);
		link.ServerPid = (uint32_t)pair;
		link.Count = counter.Count;
		link.FirstSeen = counter.FirstSeen;
		link.LastSeen = counter.LastSeen;
		links.push_back(std::move(link));
	}
	for (auto& [key, counter] : m_Rpc) {
		IpcLink link;
		link.Kind = IpcKind::Rpc;
		link.ClientPid = key.ClientPid;
		link.Interface = key.Interface;
		link.Protocol = key.Protocol;
		link.Endpoint = key.Endpoint;
		link.NetworkAddress = key.NetworkAddress;
		// a local endpoint's server, once a call on it was seen there
		if (key.NetworkAddress.empty())
			if (auto it = m_Endpoints.find(EndpointKey(key.Protocol, key.Endpoint)); it != m_Endpoints.end())
				link.ServerPid = it->second;
		link.Count = counter.Count;
		link.FirstSeen = counter.FirstSeen;
		link.LastSeen = counter.LastSeen;
		links.push_back(std::move(link));
	}
	return links;
}

void IpcTracker::RemoveProcess(uint32_t pid) {
	auto lock = m_Lock.lock_exclusive();
	std::erase_if(m_Alpc, [&](auto const& a) { return (uint32_t)(a.first >> 32) == pid || (uint32_t)a.first == pid; });
	std::erase_if(m_Rpc, [&](auto const& r) { return r.first.ClientPid == pid; });
	std::erase_if(m_Endpoints, [&](auto const& e) { return e.second == pid; });
}

DWORD WINAPI IpcTracker::ProcessThread(void* param) {
	auto tracker = static_cast<IpcTracker*>(param);
	PROCESSTRACE_HANDLE trace = tracker->m_Trace;
	return ::ProcessTrace(&trace, 1, nullptr, nullptr);
}

void WINAPI IpcTracker::OnEvent(PEVENT_RECORD record) {
	auto tracker = static_cast<IpcTracker*>(record->UserContext);
	if (record->EventHeader.ProviderId == RpcProvider)
		tracker->OnRpc(record);
	else if (record->EventHeader.ProviderId == AlpcEventClass || record->EventHeader.ProviderId == SystemAlpcProvider)
		tracker->OnAlpc(record);
}

void IpcTracker::OnAlpc(PEVENT_RECORD record) {
	auto opcode = record->EventHeader.EventDescriptor.Opcode;
	auto pid = record->EventHeader.ProcessId;
	if (opcode < AlpcSend || opcode > AlpcWaitForReply || record->UserDataLength < sizeof(uint32_t) || pid == 0 || pid == ULONG_MAX)
		return;
	uint32_t id;
	memcpy(&id, record->UserData, sizeof(id));

	auto tick = ::GetTickCount64();
	auto& message = m_Pending[id];
	if (tick - message.Tick > PendingLifetime)
		message = {};
	message.Tick = tick;
	switch (opcode) {
		case AlpcSend: message.Sender = pid; break;
		case AlpcReceive: message.Receiver = pid; break;
		// the thread waiting for the reply is the client's
		case AlpcWaitForReply: message.Client = pid; return;
	}

	if (message.Sender && message.Receiver) {
		// a request, or its reply (the same message ID), both counted for the client and server
		auto sender = message.Sender, receiver = message.Receiver;
		message.Sender = message.Receiver = 0;
		if (sender != receiver) {
			auto client = message.Client == receiver ? receiver : sender;
			auto server = client == sender ? receiver : sender;
			auto lock = m_Lock.lock_exclusive();
			m_Alpc[((uint64_t)client << 32) | server].Add(Now());
		}
	}

	// messages whose other events never came (lost, or before the session started)
	if (tick - m_LastPrune > 30000) {
		m_LastPrune = tick;
		std::erase_if(m_Pending, [&](auto const& p) { return tick - p.second.Tick > PendingLifetime; });
	}
}

void IpcTracker::OnRpc(PEVENT_RECORD record) {
	auto id = record->EventHeader.EventDescriptor.Id;
	auto data = static_cast<BYTE const*>(record->UserData);
	size_t size = record->UserDataLength;
	if ((id != ClientCallStart && id != ServerCallStart) || size < sizeof(GUID) + 2 * sizeof(uint32_t))
		return;
	GUID iface;
	memcpy(&iface, data, sizeof(iface));
	uint32_t protocol;
	memcpy(&protocol, data + sizeof(GUID) + sizeof(uint32_t), sizeof(protocol));

	size_t offset = sizeof(GUID) + 2 * sizeof(uint32_t);
	auto readString = [&] {
		if (offset >= size)
			return std::wstring();
		auto text = reinterpret_cast<wchar_t const*>(data + offset);
		auto length = ::wcsnlen(text, (size - offset) / sizeof(wchar_t));
		offset += (length + 1) * sizeof(wchar_t);
		return std::wstring(text, length);
	};
	auto address = readString();
	auto endpoint = readString();
	// no address: a local call
	if (address == L"NULL")
		address.clear();

	auto pid = record->EventHeader.ProcessId;
	auto lock = m_Lock.lock_exclusive();
	if (id == ServerCallStart)
		m_Endpoints[EndpointKey((RpcProtocol)protocol, endpoint)] = pid;
	else
		m_Rpc[RpcKey{ pid, iface, (RpcProtocol)protocol, std::move(endpoint), std::move(address) }].Add(Now());
}
