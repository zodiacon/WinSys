#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include "FileIo.h"
#include "EtwSession.h"
#include "Handles.h"

using namespace WinSys;

namespace {
	// Microsoft-Windows-Kernel-File
	const GUID KernelFileProvider = { 0xedd08927, 0x9cc4, 0x4e65, { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 } };
	const ULONGLONG KeywordFileName = 0x10, KeywordCreate = 0x80, KeywordRead = 0x100, KeywordWrite = 0x200;
	// the provider's event IDs
	const USHORT NameCreate = 10, Create = 12, Read = 15, Write = 16;

	// a file without I/O for this long is forgotten (milliseconds); a name or file object unused for longer too
	const ULONGLONG FileIdle = 60000, NameIdle = 120000;
	// the resolver's pass, and how many passes a file key may stay unnamed before it isn't looked for again
	const DWORD ResolveInterval = 2000;
	const int MaxAttempts = 3;
	// the drives' table is read again every this many passes
	const int DosNamesPasses = 15;

	// an event's payload, read field by field; a field past its end reads as zero
	struct Payload {
		uint8_t const* Data;
		size_t Size, PointerSize;

		uint64_t Pointer(size_t offset) const {
			uint64_t value = 0;
			if (offset + PointerSize <= Size)
				memcpy(&value, Data + offset, PointerSize);
			return value;
		}
		uint32_t UInt32(size_t offset) const {
			uint32_t value = 0;
			if (offset + sizeof(value) <= Size)
				memcpy(&value, Data + offset, sizeof(value));
			return value;
		}
		std::wstring String(size_t offset) const {
			if (offset >= Size)
				return L"";
			auto text = reinterpret_cast<wchar_t const*>(Data + offset);
			return std::wstring(text, ::wcsnlen(text, (Size - offset) / sizeof(wchar_t)));
		}
	};
}

FileIoTracker::~FileIoTracker() {
	Stop();
}

bool FileIoTracker::Start(PCWSTR sessionPrefix) {
	if (IsRunning())
		return true;

	if (!m_Stop && !m_Stop.try_create(wil::EventOptions::ManualReset, nullptr))
		return false;
	m_Stop.ResetEvent();
	m_DosNames = std::make_shared<DosNames const>();
	TRACEHANDLE session;
	auto error = Etw::StartSession(std::wstring(sessionPrefix) + L" ", m_SessionName, session);
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return false;
	}
	m_Session = session;

	error = ::EnableTraceEx2(session, &KernelFileProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
		KeywordFileName | KeywordCreate | KeywordRead | KeywordWrite, 0, 0, nullptr);
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

void FileIoTracker::Stop() {
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
	m_Files.clear();
	m_Names.clear();
	m_ObjectNames.clear();
	m_Pending.clear();
	m_Attempts.clear();
	m_StartTime = 0;
}

bool FileIoTracker::IsRunning() const {
	return m_Session != 0;
}

int64_t FileIoTracker::GetStartTime() const {
	return m_StartTime;
}

std::vector<FileIoCounters> FileIoTracker::GetFiles() const {
	auto lock = m_Lock.lock_shared();
	std::vector<FileIoCounters> files;
	files.reserve(m_Files.size());
	for (auto& [id, file] : m_Files) {
		FileIoCounters c;
		c.Pid = id.Pid;
		c.FileKey = id.Key;
		if (auto it = m_Names.find(id.Key); it != m_Names.end())
			c.Name = m_DosNames ? m_DosNames->Convert(it->second.Text) : it->second.Text;
		c.BytesRead = file.BytesRead;
		c.BytesWritten = file.BytesWritten;
		c.Reads = file.Reads;
		c.Writes = file.Writes;
		c.FirstSeen = file.FirstSeen;
		c.LastSeen = file.LastSeen;
		files.push_back(std::move(c));
	}
	return files;
}

void FileIoTracker::RemoveProcess(uint32_t pid) {
	auto lock = m_Lock.lock_exclusive();
	std::erase_if(m_Files, [&](auto const& f) { return f.first.Pid == pid; });
}

DWORD WINAPI FileIoTracker::ProcessThread(void* param) {
	auto tracker = static_cast<FileIoTracker*>(param);
	PROCESSTRACE_HANDLE trace = tracker->m_Trace;
	return ::ProcessTrace(&trace, 1, nullptr, nullptr);
}

void WINAPI FileIoTracker::OnEvent(PEVENT_RECORD record) {
	auto& header = record->EventHeader;
	if (header.ProviderId != KernelFileProvider)
		return;
	auto tracker = static_cast<FileIoTracker*>(record->UserContext);
	Payload data{ static_cast<uint8_t const*>(record->UserData), record->UserDataLength,
		(header.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4u : 8u };
	auto p = data.PointerSize;
	bool v0 = header.EventDescriptor.Version == 0;

	switch (header.EventDescriptor.Id) {
		case NameCreate:
		{
			// FileKey, FileName
			auto key = data.Pointer(0);
			auto name = data.String(p);
			if (key && !name.empty()) {
				auto lock = tracker->m_Lock.lock_exclusive();
				tracker->m_Names[key] = { std::move(name), ::GetTickCount64() };
				tracker->m_Pending.erase(key);
			}
			break;
		}
		case Create:
		{
			// v0: Irp, ThreadId (a pointer), FileObject, CreateOptions, CreateAttributes, ShareAccess, FileName
			// v1: Irp, FileObject, IssuingThreadId (UInt32), CreateOptions, CreateAttributes, ShareAccess, FileName
			auto fileObject = data.Pointer(v0 ? 2 * p : p);
			auto name = data.String(v0 ? 3 * p + 12 : 2 * p + 16);
			if (fileObject && !name.empty()) {
				auto lock = tracker->m_Lock.lock_exclusive();
				tracker->m_ObjectNames[fileObject] = { std::move(name), ::GetTickCount64() };
			}
			break;
		}
		case Read: case Write:
		{
			// v0: ByteOffset, Irp, ThreadId (a pointer), FileObject, FileKey, IOSize, IOFlags
			// v1: ByteOffset, Irp, FileObject, FileKey, IssuingThreadId (UInt32), IOSize, IOFlags, ExtraFlags
			uint64_t fileObject, key;
			uint32_t size;
			if (v0) {
				fileObject = data.Pointer(8 + 2 * p);
				key = data.Pointer(8 + 3 * p);
				size = data.UInt32(8 + 4 * p);
			}
			else {
				fileObject = data.Pointer(8 + p);
				key = data.Pointer(8 + 2 * p);
				size = data.UInt32(8 + 3 * p + 4);
			}
			// the header's process is the one the I/O was issued in
			tracker->OnReadWrite(fileObject, key ? key : fileObject, header.ProcessId, size, header.EventDescriptor.Id == Write);
			break;
		}
	}
}

void FileIoTracker::OnReadWrite(uint64_t fileObject, uint64_t key, uint32_t pid, uint32_t size, bool write) {
	if (!key)
		return;
	int64_t time;
	::GetSystemTimeAsFileTime((FILETIME*)&time);
	auto tick = ::GetTickCount64();

	auto lock = m_Lock.lock_exclusive();
	auto& file = m_Files[{ pid, key }];
	if (!file.FirstSeen)
		file.FirstSeen = time;
	file.LastSeen = time;
	file.LastTick = tick;
	if (write) {
		file.BytesWritten += size;
		file.Writes++;
	}
	else {
		file.BytesRead += size;
		file.Reads++;
	}

	if (auto it = m_Names.find(key); it != m_Names.end())
		it->second.Tick = tick;
	else if (auto obj = m_ObjectNames.find(fileObject); obj != m_ObjectNames.end())
		// opened while the session ran: the Create event named its file object
		m_Names[key] = { obj->second.Text, tick };
	else if (auto attempts = m_Attempts.find(key); attempts == m_Attempts.end() || attempts->second < MaxAttempts)
		// for the resolver, through a handle to the file object
		m_Pending[key] = fileObject;
}

DWORD WINAPI FileIoTracker::ResolverThread(void* param) {
	auto tracker = static_cast<FileIoTracker*>(param);
	ObjectNameQuery nameQuery;
	for (int pass = 1; ::WaitForSingleObject(tracker->m_Stop.get(), ResolveInterval) == WAIT_TIMEOUT; pass++) {
		if (pass % DosNamesPasses == 0) {
			auto dosNames = std::make_shared<DosNames const>();
			auto lock = tracker->m_Lock.lock_exclusive();
			tracker->m_DosNames = std::move(dosNames);
		}
		tracker->Resolve(nameQuery);
		tracker->Prune();
	}
	return 0;
}

void FileIoTracker::Resolve(ObjectNameQuery& nameQuery) {
	std::unordered_map<uint64_t, uint64_t> pending;
	std::shared_ptr<DosNames const> dosNames;
	{
		auto lock = m_Lock.lock_exclusive();
		pending.swap(m_Pending);
		dosNames = m_DosNames;
	}
	if (pending.empty())
		return;

	// the file objects' handles, from the system's table (about 30 ms)
	HandleEnumerator enumerator;
	auto handles = enumerator.EnumSystemHandles();
	if (!handles)
		return;
	std::unordered_map<uint16_t, bool> fileTypes;
	std::unordered_map<uint64_t, SystemHandleEntry const*> byObject;
	for (auto& h : *handles) {
		auto type = fileTypes.find(h.TypeIndex);
		if (type == fileTypes.end())
			type = fileTypes.emplace(h.TypeIndex, ObjectTypes::GetName(h.TypeIndex) == L"File").first;
		if (type->second && h.Object)
			byObject.try_emplace((uint64_t)h.Object, &h);
	}

	std::unordered_map<uint32_t, wil::unique_handle> processes;
	std::vector<std::pair<uint64_t, std::wstring>> names;
	std::vector<uint64_t> unnamed;
	for (auto& [key, fileObject] : pending) {
		auto it = byObject.find(fileObject);
		std::wstring name;
		if (it != byObject.end()) {
			auto& entry = *it->second;
			auto& hProcess = processes[entry.Pid];
			if (!hProcess)
				hProcess.reset(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, entry.Pid));
			if (hProcess)
				name = HandleNames::QueryName(hProcess.get(), entry, nameQuery, *dosNames, {});
		}
		if (name.empty())
			unnamed.push_back(key);
		else
			names.push_back({ key, std::move(name) });
	}

	auto tick = ::GetTickCount64();
	auto lock = m_Lock.lock_exclusive();
	for (auto& [key, name] : names)
		m_Names.try_emplace(key, Name{ std::move(name), tick });
	for (auto key : unnamed)
		m_Attempts[key]++;
}

void FileIoTracker::Prune() {
	auto tick = ::GetTickCount64();
	auto lock = m_Lock.lock_exclusive();
	std::erase_if(m_Files, [&](auto const& f) { return tick - f.second.LastTick > FileIdle; });
	std::erase_if(m_Names, [&](auto const& n) { return tick - n.second.Tick > NameIdle; });
	std::erase_if(m_ObjectNames, [&](auto const& n) { return tick - n.second.Tick > NameIdle; });
	// the attempts of the keys still in use
	std::unordered_set<uint64_t> keys;
	for (auto& [id, file] : m_Files)
		keys.insert(id.Key);
	std::erase_if(m_Attempts, [&](auto const& a) { return !keys.contains(a.first); });
}
