#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include "RegistryIo.h"
#include "EtwSession.h"
#include "Handles.h"

using namespace WinSys;

namespace {
	// Microsoft-Windows-Kernel-Registry
	const GUID KernelRegistryProvider = { 0x70eb4f03, 0xc1de, 0x4f73, { 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd } };
	// every operation's keyword but CloseKey (0x1) and FlushKey (0x80): closes are the most frequent events, and neither
	// counts
	const ULONGLONG Keywords = 0xFF7E;

	// the resolver's pass (milliseconds): how long an operation on a key object opened before the session may wait
	const DWORD ResolveInterval = 1000;

	const uint32_t StatusReparse = 0x104, StatusBufferTooSmall = 0xC0000023;
	const uint32_t RegCreatedNewKey = 1;

	// an event's payload, read field by field in order; a field past its end reads as zero (or empty)
	struct Reader {
		uint8_t const* Data;
		size_t Size, PointerSize;
		size_t Offset{ 0 };

		uint64_t Pointer() {
			uint64_t value = 0;
			if (Offset + PointerSize <= Size)
				memcpy(&value, Data + Offset, PointerSize);
			Offset += PointerSize;
			return value;
		}
		uint32_t UInt32() {
			uint32_t value = 0;
			if (Offset + sizeof(value) <= Size)
				memcpy(&value, Data + Offset, sizeof(value));
			Offset += sizeof(value);
			return value;
		}
		// a NUL-terminated UTF-16 string, past its terminator
		std::wstring String() {
			if (Offset >= Size)
				return L"";
			auto text = reinterpret_cast<wchar_t const*>(Data + Offset);
			auto len = ::wcsnlen(text, (Size - Offset) / sizeof(wchar_t));
			Offset += (len + 1) * sizeof(wchar_t);
			return std::wstring(text, len);
		}
	};

	std::wstring Upper(std::wstring const& text) {
		std::wstring upper(text);
		for (auto& c : upper)
			c = ::RtlUpcaseUnicodeChar(c);
		return upper;
	}

	std::wstring Hex(uint64_t value) {
		WCHAR text[32];
		::StringCchPrintf(text, _countof(text), L"%llX", value);
		return text;
	}

	// a row's key for an unnamed key object
	std::wstring ObjectText(uint64_t object) {
		return L"#" + Hex(object);
	}
}

//
// RegistryIoParser
//

std::optional<RegistryEvent> RegistryIoParser::Parse(uint16_t id, void const* data, size_t size, size_t pointerSize) {
	using Op = RegistryOperation;
	if (id < (uint16_t)Op::CreateKey || id > (uint16_t)Op::SetSecurity)
		return std::nullopt;
	RegistryEvent e;
	e.Operation = (Op)id;
	Reader r{ static_cast<uint8_t const*>(data), size, pointerSize };
	switch (e.Operation) {
		case Op::CreateKey: case Op::OpenKey:
			// BaseObject, KeyObject, Status, Disposition, BaseName (empty in practice), RelativeName
		{
			e.BaseObject = r.Pointer();
			e.KeyObject = r.Pointer();
			e.Status = r.UInt32();
			e.Disposition = r.UInt32();
			auto base = r.String();
			auto relative = r.String();
			e.Name = base.empty() ? std::move(relative) : relative.empty() ? std::move(base) : base + L"\\" + relative;
			break;
		}
		case Op::SetValue:
			// KeyObject, Status, Type, DataSize, KeyName, ValueName, ...
		case Op::QueryValue:
			// KeyObject, Status, InfoClass, DataSize, KeyName, ValueName, ...
			e.KeyObject = r.Pointer();
			e.Status = r.UInt32();
			r.UInt32();
			r.UInt32();
			r.String();
			e.ValueName = r.String();
			break;
		case Op::DeleteValue:
			// KeyObject, Status, KeyName, ValueName
			e.KeyObject = r.Pointer();
			e.Status = r.UInt32();
			r.String();
			e.ValueName = r.String();
			break;
		default:
			// KeyObject, Status, then fields that don't count (and KeyName, which is empty)
			e.KeyObject = r.Pointer();
			e.Status = r.UInt32();
			break;
	}
	return e;
}

PCWSTR RegistryIoParser::OperationName(RegistryOperation op) {
	using Op = RegistryOperation;
	switch (op) {
		case Op::CreateKey: return L"Create Key";
		case Op::OpenKey: return L"Open Key";
		case Op::DeleteKey: return L"Delete Key";
		case Op::QueryKey: return L"Query Key";
		case Op::SetValue: return L"Set Value";
		case Op::DeleteValue: return L"Delete Value";
		case Op::QueryValue: return L"Query Value";
		case Op::EnumerateKey: return L"Enumerate Keys";
		case Op::EnumerateValue: return L"Enumerate Values";
		case Op::QueryMultipleValues: return L"Query Multiple Values";
		case Op::SetKeyInformation: return L"Set Key Information";
		case Op::FlushKey: return L"Flush Key";
		case Op::CloseKey: return L"Close Key";
		case Op::QuerySecurity: return L"Query Security";
		case Op::SetSecurity: return L"Set Security";
	}
	return L"";
}

std::wstring RegistryIoParser::ResultName(uint32_t status) {
	switch (status) {
		case 0: return L"SUCCESS";
		case 0x80000005: return L"BUFFER OVERFLOW";
		case 0x8000001A: return L"NO MORE ENTRIES";
		case 0xC0000022: return L"ACCESS DENIED";
		case StatusBufferTooSmall: return L"BUFFER TOO SMALL";
		case 0xC0000034: return L"NAME NOT FOUND";
		case 0xC000003A: return L"PATH NOT FOUND";
		case 0xC000017C: return L"KEY DELETED";
		case 0xC0000033: return L"NAME INVALID";
		case 0xC0000035: return L"NAME COLLISION";
		case 0xC0000008: return L"INVALID HANDLE";
		case 0xC000000D: return L"INVALID PARAMETER";
	}
	WCHAR text[16];
	::StringCchPrintf(text, _countof(text), L"0x%08X", status);
	return text;
}

std::wstring RegistryIoParser::UnnamedName(uint64_t object, RegistryUnnamed why) {
	auto hex = L"0x" + Hex(object);
	switch (why) {
		case RegistryUnnamed::Closed: return L"(key " + hex + L", closed)";
		case RegistryUnnamed::KernelHandle: return L"(kernel key " + hex + L")";
		case RegistryUnnamed::Protected: return L"(key " + hex + L" of a protected process)";
	}
	return L"(key " + hex + L")";
}

bool RegistryIoParser::IsRetried(uint32_t status) {
	return status == StatusReparse;
}

bool RegistryIoParser::IsFailure(uint32_t status) {
	return (status & 0xC0000000) == 0xC0000000 && status != StatusBufferTooSmall;
}

//
// RegistryIoTable
//

std::optional<std::wstring> RegistryIoTable::OpenName(RegistryEvent const& e) const {
	if (!e.Name.empty() && e.Name[0] == L'\\')
		return HandleNames::RegistryName(e.Name);
	auto it = m_Names.find(e.BaseObject);
	if (it == m_Names.end())
		return std::nullopt;
	return e.Name.empty() ? it->second.Text : it->second.Text + L"\\" + e.Name;
}

void RegistryIoTable::OnEvent(RegistryEvent e, uint32_t pid, int64_t time, uint64_t tick) {
	using Op = RegistryOperation;
	if (e.Operation == Op::None || e.Operation == Op::CloseKey || e.Operation == Op::FlushKey)
		return;
	if (e.Operation == Op::OpenKey || e.Operation == Op::CreateKey) {
		if (RegistryIoParser::IsRetried(e.Status))
			return;
		// a new key object at this address: what still waits on the address was another key's, and so were the
		// resolver's failures on it (addresses are reused all the time)
		if (e.KeyObject) {
			FlushWaiting(e.KeyObject, e.Stamp);
			m_Attempts.erase(e.KeyObject);
			// an earlier open's still waiting: the operations from now on are this key's
			m_PendingOpens.erase(e.KeyObject);
		}
		auto name = OpenName(e);
		if (name)
			Count(e, *name, pid, time, tick);
		else if (GaveUp(e.BaseObject))
			Count(e, UnnamedBase(e.BaseObject, e.Name), pid, time, tick);
		else {
			uint64_t token = 0;
			if (e.KeyObject && !RegistryIoParser::IsFailure(e.Status)) {
				// its key object's address may still have the name of a key closed since (closes aren't traced): the
				// operations that follow wait for this open (its token), not take that name
				m_Names.erase(e.KeyObject);
				token = m_NextToken++;
				m_PendingOpens[e.KeyObject] = token;
				Retarget(e.KeyObject, e.Stamp, token);
			}
			auto base = e.BaseObject;
			Defer(std::move(e), pid, time, tick, base, token);
		}
		return;
	}
	if (auto it = m_Names.find(e.KeyObject); it != m_Names.end()) {
		it->second.Tick = tick;
		Count(e, it->second.Text, pid, time, tick);
	}
	else if (auto pending = m_PendingOpens.find(e.KeyObject); pending != m_PendingOpens.end()) {
		auto token = pending->second;
		Defer(std::move(e), pid, time, tick, token);
	}
	else if (GaveUp(e.KeyObject))
		Count(e, L"", pid, time, tick);
	else {
		auto object = e.KeyObject;
		Defer(std::move(e), pid, time, tick, object);
	}
}

void RegistryIoTable::Retarget(uint64_t object, int64_t stamp, uint64_t token) {
	auto waiting = m_Waiting.find(object);
	if (waiting == m_Waiting.end())
		return;
	for (auto& d : m_Deferred)
		if (d.Waiting == object && d.Event.Stamp >= stamp) {
			d.Waiting = token;
			m_Waiting[token]++;
			--waiting->second;
		}
	if (waiting->second == 0)
		m_Waiting.erase(waiting);
}

void RegistryIoTable::NameToken(Deferred const& open, std::wstring const& name, uint64_t tick) {
	if (!open.Token)
		return;
	m_Names[open.Token] = { name, tick };
	if (auto it = m_PendingOpens.find(open.Event.KeyObject); it != m_PendingOpens.end() && it->second == open.Token)
		m_PendingOpens.erase(it);
}

bool RegistryIoTable::GaveUp(uint64_t object) const {
	auto it = m_Attempts.find(object);
	return object == 0 || (it != m_Attempts.end() && it->second.Count >= MaxAttempts);
}

RegistryUnnamed RegistryIoTable::WhyUnnamed(uint64_t object) const {
	auto it = m_Attempts.find(object);
	return it == m_Attempts.end() ? RegistryUnnamed::None : it->second.Why;
}

std::wstring RegistryIoTable::UnnamedBase(uint64_t base, std::wstring const& relative) const {
	return RegistryIoParser::UnnamedName(base, WhyUnnamed(base)) + L"\\" + relative;
}

void RegistryIoTable::Defer(RegistryEvent e, uint32_t pid, int64_t time, uint64_t tick, uint64_t waiting, uint64_t token) {
	if (m_Deferred.size() >= MaxDeferred) {
		// too many waiting: counted at once, unnamed (an operation waiting on an open's token, under that name)
		auto open = e.Operation == RegistryOperation::OpenKey || e.Operation == RegistryOperation::CreateKey;
		if (open) {
			auto name = UnnamedBase(waiting, e.Name);
			Count(e, name, pid, time, tick);
			NameToken({ e, pid, time, tick, waiting, token }, name, tick);
		}
		else if (auto it = m_Names.find(waiting); IsToken(waiting) && it != m_Names.end())
			Count(e, it->second.Text, pid, time, tick);
		else
			Count(e, L"", pid, time, tick);
		return;
	}
	// a token isn't for the resolver: its open names it
	if (m_Waiting[waiting]++ == 0 && !IsToken(waiting))
		m_Unnamed.insert(waiting);
	m_Deferred.push_back({ std::move(e), pid, time, tick, waiting, token });
}

void RegistryIoTable::Count(RegistryEvent const& e, std::wstring const& name, uint32_t pid, int64_t time, uint64_t tick, bool nameObject) {
	using Op = RegistryOperation;
	bool open = e.Operation == Op::OpenKey || e.Operation == Op::CreateKey;
	// an operation on a key object without a name counts under the object
	auto object = name.empty() ? e.KeyObject : 0;
	auto& row = m_Rows[{ pid, name.empty() ? ObjectText(object) : Upper(name) }];
	auto& c = row.Counters;
	if (!c.FirstSeen) {
		c.Pid = pid;
		c.Key = name;
		c.Object = object;
		c.Unnamed = object ? WhyUnnamed(object) : RegistryUnnamed::None;
		c.FirstSeen = time;
	}
	c.LastSeen = time;
	row.LastTick = tick;
	c.LastOperation = e.Operation;
	c.LastStatus = e.Status;
	switch (e.Operation) {
		case Op::CreateKey:
			c.Opens++;
			if (e.Disposition == RegCreatedNewKey)
				c.Writes++;
			break;
		case Op::OpenKey:
			c.Opens++;
			break;
		case Op::QueryKey: case Op::QueryValue: case Op::EnumerateKey: case Op::EnumerateValue:
		case Op::QueryMultipleValues: case Op::QuerySecurity:
			c.Reads++;
			break;
		default:
			c.Writes++;
			break;
	}
	if (RegistryIoParser::IsFailure(e.Status))
		c.Failures++;
	if (e.Operation == Op::QueryValue || e.Operation == Op::SetValue || e.Operation == Op::DeleteValue)
		c.LastValue = e.ValueName;

	// an open names its key object for the operations that follow
	if (open && nameObject && e.KeyObject && !name.empty() && !RegistryIoParser::IsFailure(e.Status))
		m_Names[e.KeyObject] = { name, tick };
}

void RegistryIoTable::FlushWaiting(uint64_t object, int64_t stamp) {
	auto waiting = m_Waiting.find(object);
	if (waiting == m_Waiting.end())
		return;
	// the earlier ones count under the object, as a closed one's (the caller then forgets the attempts)
	m_Attempts[object] = { MaxAttempts, RegistryUnnamed::Closed };
	std::deque<Deferred> keep;
	for (auto& d : m_Deferred) {
		if (d.Waiting != object || d.Event.Stamp >= stamp) {
			keep.push_back(std::move(d));
			continue;
		}
		auto& e = d.Event;
		bool open = e.Operation == RegistryOperation::OpenKey || e.Operation == RegistryOperation::CreateKey;
		Count(e, open ? UnnamedBase(object, e.Name) : L"", d.Pid, d.Time, d.Tick);
		--waiting->second;
	}
	if (waiting->second == 0)
		m_Waiting.erase(waiting);
	m_Deferred.swap(keep);
}

std::vector<uint64_t> RegistryIoTable::TakeUnnamed() {
	std::vector<uint64_t> objects(m_Unnamed.begin(), m_Unnamed.end());
	m_Unnamed.clear();
	return objects;
}

void RegistryIoTable::SetName(uint64_t object, std::wstring const& name, uint64_t tick) {
	m_Names[object] = { HandleNames::RegistryName(name), tick };
}

void RegistryIoTable::NameFailed(uint64_t object, RegistryUnnamed why) {
	auto& attempts = m_Attempts[object];
	attempts.Count++;
	attempts.Why = why;
}

void RegistryIoTable::ApplyDeferred() {
	std::deque<Deferred> waiting;
	for (auto& d : m_Deferred) {
		auto& e = d.Event;
		bool ready = m_Names.contains(d.Waiting) || GaveUp(d.Waiting);
		if (!ready) {
			waiting.push_back(std::move(d));
			continue;
		}
		auto it = m_Waiting.find(d.Waiting);
		if (it != m_Waiting.end() && --it->second == 0)
			m_Waiting.erase(it);

		if (e.Operation == RegistryOperation::OpenKey || e.Operation == RegistryOperation::CreateKey) {
			auto name = OpenName(e);
			auto text = name ? *name : UnnamedBase(e.BaseObject, e.Name);
			// it names its key object only if no later open took the address meanwhile
			auto pending = m_PendingOpens.find(e.KeyObject);
			Count(e, text, d.Pid, d.Time, d.Tick, pending != m_PendingOpens.end() && pending->second == d.Token);
			NameToken(d, text, d.Tick);
		}
		// by what it waited on: its key object's name, or its open's (the address may have another key's by now)
		else if (auto name = m_Names.find(d.Waiting); name != m_Names.end()) {
			name->second.Tick = (std::max)(name->second.Tick, d.Tick);
			Count(e, name->second.Text, d.Pid, d.Time, d.Tick);
		}
		else
			Count(e, L"", d.Pid, d.Time, d.Tick);
	}
	m_Deferred.swap(waiting);
	// the objects still waiting go to the resolver again (not the tokens: their opens name them)
	for (auto& [object, count] : m_Waiting)
		if (!IsToken(object))
			m_Unnamed.insert(object);
}

std::vector<RegistryIoCounters> RegistryIoTable::GetKeys() const {
	std::vector<RegistryIoCounters> keys;
	keys.reserve(m_Rows.size());
	for (auto& [id, row] : m_Rows)
		keys.push_back(row.Counters);
	return keys;
}

size_t RegistryIoTable::GetDeferredCount() const {
	return m_Deferred.size();
}

void RegistryIoTable::RemoveProcess(uint32_t pid) {
	std::erase_if(m_Rows, [&](auto const& r) { return r.first.Pid == pid; });
}

void RegistryIoTable::Prune(uint64_t tick) {
	std::erase_if(m_Rows, [&](auto const& r) { return tick - r.second.LastTick > KeyIdle; });
	std::erase_if(m_Names, [&](auto const& n) { return tick - n.second.Tick > NameIdle; });
	// the attempts of the objects still waited on
	std::erase_if(m_Attempts, [&](auto const& a) { return !m_Waiting.contains(a.first); });
}

void RegistryIoTable::Clear() {
	m_Rows.clear();
	m_Names.clear();
	m_Deferred.clear();
	m_Waiting.clear();
	m_Unnamed.clear();
	m_Attempts.clear();
	m_PendingOpens.clear();
}

//
// RegistryIoTracker
//

RegistryIoTracker::~RegistryIoTracker() {
	Stop();
}

bool RegistryIoTracker::Start(PCWSTR sessionPrefix) {
	if (IsRunning())
		return true;

	if (!m_Stop && !m_Stop.try_create(wil::EventOptions::ManualReset, nullptr))
		return false;
	m_Stop.ResetEvent();
	TRACEHANDLE session;
	auto error = Etw::StartSession(std::wstring(sessionPrefix) + L" ", m_SessionName, session);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return false;
	}
	m_Session = session;

	error = ::EnableTraceEx2(session, &KernelRegistryProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
		Keywords, 0, 0, nullptr);
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
			m_hResolver.reset(::CreateThread(nullptr, 0, ResolverThread, this, 0, nullptr));
			if (!m_hThread || !m_hResolver)
				error = ::GetLastError();
		}
	}
	if (error != ERROR_SUCCESS) {
		Stop();
		::SetLastError(error);
		return false;
	}
	::GetSystemTimeAsFileTime((FILETIME*)&m_StartTime);
	return true;
}

void RegistryIoTracker::Stop() {
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
	if (m_Stop)
		m_Stop.SetEvent();
	for (auto h : { m_hThread.get(), m_hResolver.get() })
		if (h)
			::WaitForSingleObject(h, INFINITE);
	m_hThread.reset();
	m_hResolver.reset();
	auto lock = m_Lock.lock_exclusive();
	m_Table.Clear();
	m_StartTime = 0;
}

bool RegistryIoTracker::IsRunning() const {
	return m_Session != 0;
}

int64_t RegistryIoTracker::GetStartTime() const {
	return m_StartTime;
}

std::vector<RegistryIoCounters> RegistryIoTracker::GetKeys() const {
	auto lock = m_Lock.lock_shared();
	return m_Table.GetKeys();
}

size_t RegistryIoTracker::GetDeferredCount() const {
	auto lock = m_Lock.lock_shared();
	return m_Table.GetDeferredCount();
}

uint64_t RegistryIoTracker::GetLostEvents() const {
	if (!m_Session)
		return 0;
	auto props = Etw::MakeProperties();
	if (::ControlTrace(m_Session, nullptr, &props.Properties, EVENT_TRACE_CONTROL_QUERY) != ERROR_SUCCESS)
		return 0;
	return (uint64_t)props.Properties.EventsLost + props.Properties.RealTimeBuffersLost;
}

void RegistryIoTracker::RemoveProcess(uint32_t pid) {
	auto lock = m_Lock.lock_exclusive();
	m_Table.RemoveProcess(pid);
}

DWORD WINAPI RegistryIoTracker::ProcessThread(void* param) {
	auto tracker = static_cast<RegistryIoTracker*>(param);
	PROCESSTRACE_HANDLE trace = tracker->m_Trace;
	return ::ProcessTrace(&trace, 1, nullptr, nullptr);
}

void WINAPI RegistryIoTracker::OnEvent(PEVENT_RECORD record) {
	auto& header = record->EventHeader;
	if (header.ProviderId != KernelRegistryProvider)
		return;
	auto e = RegistryIoParser::Parse(header.EventDescriptor.Id, record->UserData, record->UserDataLength,
		(header.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4u : 8u);
	if (!e)
		return;
	// system time as the consumer gets it (100 ns units, as the live runs showed): it only orders the events
	e->Stamp = header.TimeStamp.QuadPart;
	auto tracker = static_cast<RegistryIoTracker*>(record->UserContext);
	int64_t time;
	::GetSystemTimeAsFileTime((FILETIME*)&time);
	auto tick = ::GetTickCount64();
	auto lock = tracker->m_Lock.lock_exclusive();
	// the header's process is the one the operation was issued in
	tracker->m_Table.OnEvent(std::move(*e), header.ProcessId, time, tick);
}

DWORD WINAPI RegistryIoTracker::ResolverThread(void* param) {
	auto tracker = static_cast<RegistryIoTracker*>(param);
	while (::WaitForSingleObject(tracker->m_Stop.get(), ResolveInterval) == WAIT_TIMEOUT)
		tracker->Resolve();
	return 0;
}

void RegistryIoTracker::Resolve() {
	std::vector<uint64_t> objects;
	{
		auto lock = m_Lock.lock_exclusive();
		objects = m_Table.TakeUnnamed();
	}

	std::vector<std::pair<uint64_t, std::wstring>> names;
	std::vector<std::pair<uint64_t, RegistryUnnamed>> unnamed;
	if (!objects.empty()) {
		// the key objects' handles, from the system's table (about 30 ms)
		HandleEnumerator enumerator;
		auto handles = enumerator.EnumSystemHandles();
		std::unordered_map<uint16_t, bool> keyTypes;
		// every handle to each key object wanted: a kernel key (System's handle, which can't be duplicated) may have
		// one in a process too, as may a protected process's
		std::unordered_set<uint64_t> wanted(objects.begin(), objects.end());
		std::unordered_map<uint64_t, std::vector<SystemHandleEntry const*>> byObject;
		if (handles)
			for (auto& h : *handles) {
				if (!h.Object || !wanted.contains((uint64_t)h.Object))
					continue;
				auto type = keyTypes.find(h.TypeIndex);
				if (type == keyTypes.end())
					type = keyTypes.emplace(h.TypeIndex, ObjectTypes::GetName(h.TypeIndex) == L"Key").first;
				if (type->second)
					byObject[(uint64_t)h.Object].push_back(&h);
			}
		ObjectNameQuery nameQuery;
		DosNames dosNames;
		// the processes opened for duplicating, null for those that refused
		std::unordered_map<uint32_t, wil::unique_handle> processes;
		for (auto object : objects) {
			std::wstring name;
			auto why = RegistryUnnamed::Closed;
			if (auto it = byObject.find(object); it != byObject.end()) {
				why = RegistryUnnamed::KernelHandle;
				for (auto entry : it->second) {
					if (entry->Pid == 4)
						continue;
					why = RegistryUnnamed::Protected;
					auto [process, added] = processes.try_emplace(entry->Pid);
					if (added)
						process->second.reset(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, entry->Pid));
					if (process->second)
						// a key's name is queried directly (only a file's can hang)
						name = HandleNames::QueryName(process->second.get(), *entry, nameQuery, dosNames, {}, false);
					if (!name.empty())
						break;
				}
			}
			if (name.empty())
				unnamed.push_back({ object, why });
			else
				names.push_back({ object, std::move(name) });
		}
	}

	auto tick = ::GetTickCount64();
	auto lock = m_Lock.lock_exclusive();
	for (auto& [object, name] : names)
		m_Table.SetName(object, name, tick);
	for (auto [object, why] : unnamed)
		m_Table.NameFailed(object, why);
	m_Table.ApplyDeferred();
	m_Table.Prune(tick);
}
