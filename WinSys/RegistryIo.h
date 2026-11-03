#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <wil/resource.h>

//
// Registry I/O per process and key, counted from an ETW real-time session on the Microsoft-Windows-Kernel-Registry
// provider (administrator rights needed, as for FileIoTracker). Its events (all version 0) name a key only when it's
// opened or created (an absolute \REGISTRY\... name, or one relative to the base key object the open was given); the
// other operations carry the key object alone, with an empty KeyName. So a key object is named by its open, and one
// opened before the session started (or relative to such a one, as HKCU's predefined handle) by a resolver thread of
// the tracker's own, which looks it up in the system's handle table. An operation on a key object not named yet waits
// for the resolver (RegistryIoTable's deferred operations), then counts under the key's name; one the resolver can't
// name counts under the object ("(key 0x...)"). Names are shown as the registry editor shows them (HKLM\...,
// HKCU\...). A key with no operation for a minute is forgotten.
//

struct _EVENT_RECORD;	// evntcons.h

namespace WinSys {
	// Microsoft-Windows-Kernel-Registry's event IDs, one per operation (and keyword)
	enum class RegistryOperation : uint8_t {
		None, CreateKey, OpenKey, DeleteKey, QueryKey, SetValue, DeleteValue, QueryValue, EnumerateKey, EnumerateValue,
		QueryMultipleValues, SetKeyInformation, FlushKey, CloseKey, QuerySecurity, SetSecurity,
	};

	// why a key object couldn't be named: the resolver found no handle to it (closed since), only the kernel's (the
	// System process's, which can't be duplicated), or only protected processes' (which refuse PROCESS_DUP_HANDLE)
	enum class RegistryUnnamed : uint8_t {
		None, Closed, KernelHandle, Protected,
	};

	// an event's fields, as far as the counting needs them
	struct RegistryEvent {
		RegistryOperation Operation{ RegistryOperation::None };
		uint64_t KeyObject{ 0 };	// zero for an open or create that failed
		uint64_t BaseObject{ 0 };	// open, create: the key Name is relative to (unless it's absolute)
		uint32_t Status{ 0 };		// NTSTATUS
		uint32_t Disposition{ 0 };	// create: REG_CREATED_NEW_KEY (1) or REG_OPENED_EXISTING_KEY (2)
		// the event header's time stamp (a real-time consumer gets it as system time): the session delivers each
		// processor's buffer as it fills, so an operation may arrive before the open (on another processor) that named
		// its key object
		int64_t Stamp{ 0 };
		std::wstring Name;			// open, create: \REGISTRY\... or relative to BaseObject
		std::wstring ValueName;		// query, set and delete value
	};

	struct RegistryIoParser final {
		// an event's payload (UserData) by its ID; nothing for an ID that isn't an operation's. pointerSize: 4 when the
		// header has EVENT_HEADER_FLAG_32_BIT_HEADER, else 8
		[[nodiscard]] static std::optional<RegistryEvent> Parse(uint16_t id, void const* data, size_t size, size_t pointerSize);
		// "Open", "Query Value"...
		[[nodiscard]] static PCWSTR OperationName(RegistryOperation op);
		// Process Monitor's words for the common results ("SUCCESS", "NAME NOT FOUND"), else the NTSTATUS in hex
		[[nodiscard]] static std::wstring ResultName(uint32_t status);
		// "(kernel key 0x...)", "(key 0x... of a protected process)"...: a key object that couldn't be named
		[[nodiscard]] static std::wstring UnnamedName(uint64_t object, RegistryUnnamed why);
		// STATUS_REPARSE: the open is retried by the kernel with the name it reparsed to (a symbolic link's)
		[[nodiscard]] static bool IsRetried(uint32_t status);
		// an error, other than a buffer too small (a size probe the caller follows with the real query)
		[[nodiscard]] static bool IsFailure(uint32_t status);
	};

	struct RegistryIoCounters {
		uint32_t Pid{ 0 };
		std::wstring Key;		// HKLM\..., HKCU\...; empty for a key object that couldn't be named (Object)
		uint64_t Object{ 0 };	// the unnamed key object; zero for a named key
		RegistryUnnamed Unnamed{ RegistryUnnamed::None };	// why it couldn't be named
		// opens and creates; queries and enumerations; sets, deletes, new keys; failed operations (any of them)
		uint64_t Opens{ 0 }, Reads{ 0 }, Writes{ 0 }, Failures{ 0 };
		RegistryOperation LastOperation{ RegistryOperation::None };
		uint32_t LastStatus{ 0 };
		std::wstring LastValue;	// the last value queried, set or deleted
		int64_t FirstSeen{ 0 }, LastSeen{ 0 };	// FILETIME

		[[nodiscard]] uint64_t Operations() const {
			return Opens + Reads + Writes;
		}
	};

	//
	// The counting and naming, apart from the session, so tests can drive it. Not thread safe: the tracker locks.
	//
	class RegistryIoTable {
	public:
		// a key object the resolver gave up on after this many passes (seconds) counts unnamed
		static constexpr int MaxAttempts = 3;
		// operations waiting for a name past this count unnamed at once
		static constexpr size_t MaxDeferred = 100000;
		// milliseconds: a key without operations is forgotten after KeyIdle, a key object's name unused after NameIdle
		static constexpr uint64_t KeyIdle = 60000, NameIdle = 120000;

		void OnEvent(RegistryEvent e, uint32_t pid, int64_t time, uint64_t tick);
		// the key objects operations wait on, for the resolver (and forgotten: the next pass gets the ones still waiting)
		[[nodiscard]] std::vector<uint64_t> TakeUnnamed();
		// the resolver's name for a key object (an NT name or the registry editor's)
		void SetName(uint64_t object, std::wstring const& name, uint64_t tick);
		// the resolver couldn't name it this pass, and why
		void NameFailed(uint64_t object, RegistryUnnamed why = RegistryUnnamed::Closed);
		// counts the waiting operations whose key objects were named or given up on since
		void ApplyDeferred();
		[[nodiscard]] std::vector<RegistryIoCounters> GetKeys() const;
		[[nodiscard]] size_t GetDeferredCount() const;
		void RemoveProcess(uint32_t pid);
		void Prune(uint64_t tick);
		void Clear();

	private:
		struct RowId {
			uint32_t Pid;
			std::wstring Key;	// the name upper-cased, or "#<object>" for an unnamed key object
			bool operator==(RowId const&) const = default;
		};
		struct RowIdHash {
			size_t operator()(RowId const& id) const noexcept {
				return std::hash<std::wstring>()(id.Key) ^ (std::hash<uint32_t>()(id.Pid) << 1);
			}
		};
		struct Row {
			RegistryIoCounters Counters;
			uint64_t LastTick{ 0 };
		};
		struct Name {
			std::wstring Text;	// the registry editor's form
			uint64_t Tick{ 0 };
		};
		struct Deferred {
			RegistryEvent Event;
			uint32_t Pid;
			int64_t Time;
			uint64_t Tick;
			// what it waits on to be named: its key object, the base for an open by a relative name, or the token of
			// its key object's open that waits itself
			uint64_t Waiting;
			uint64_t Token;	// an open that waits: the token its key object's operations wait on meanwhile; else 0
		};

		// A waiting open's key object: the operations that follow it wait on the open (its token), not on the address,
		// which another key may take meanwhile (closes aren't traced), its open then flushing what waits on the
		// address. Tokens are values no key object has (kernel addresses are above 0x8000000000000000; the tests'
		// small values are below)
		static constexpr uint64_t TokenBase = 0x7FFF000000000000;
		static bool IsToken(uint64_t value) {
			return value >= TokenBase && value < 0x8000000000000000;
		}

		// the name an open or create gives its key, once its base is known; nothing while it isn't
		std::optional<std::wstring> OpenName(RegistryEvent const& e) const;
		void Defer(RegistryEvent e, uint32_t pid, int64_t time, uint64_t tick, uint64_t waiting, uint64_t token = 0);
		// what waits on a key object from stamp on (it arrived before its open, on another processor) waits on the open's
		// token instead
		void Retarget(uint64_t object, int64_t stamp, uint64_t token);
		// an open counted under name: its token (if it waited) is named too, for the operations waiting on it
		void NameToken(Deferred const& open, std::wstring const& name, uint64_t tick);
		// counts an event under the key's name (empty: under the key object, unnamed); an open names its key object for
		// the operations that follow, unless nameObject is false (a waiting open whose address a later open took)
		void Count(RegistryEvent const& e, std::wstring const& name, uint32_t pid, int64_t time, uint64_t tick, bool nameObject = true);
		// a key object opened at stamp: the operations waiting on it from before were another key's at the address (closed
		// since), counted under the object; those from after are this key's, which they wait for the next ApplyDeferred
		// to count under its name (they arrived first). Leaves the object given up on: the caller forgets its attempts
		void FlushWaiting(uint64_t object, int64_t stamp);
		[[nodiscard]] bool GaveUp(uint64_t object) const;
		[[nodiscard]] RegistryUnnamed WhyUnnamed(uint64_t object) const;
		// the name of a key opened relative to a key object that couldn't be named
		[[nodiscard]] std::wstring UnnamedBase(uint64_t base, std::wstring const& relative) const;

		std::unordered_map<RowId, Row, RowIdHash> m_Rows;
		std::unordered_map<uint64_t, Name> m_Names;	// by key object
		std::deque<Deferred> m_Deferred;
		std::unordered_map<uint64_t, int> m_Waiting;	// key objects operations wait on, and how many
		std::unordered_set<uint64_t> m_Unnamed;			// of those, the ones not given to the resolver yet
		struct Attempts {
			int Count{ 0 };
			RegistryUnnamed Why{ RegistryUnnamed::None };	// the last pass's
		};
		std::unordered_map<uint64_t, Attempts> m_Attempts;	// the resolver's failed passes per key object
		std::unordered_map<uint64_t, uint64_t> m_PendingOpens;	// key objects whose open waits, to its token
		uint64_t m_NextToken{ TokenBase };
	};

	class RegistryIoTracker {
	public:
		RegistryIoTracker() = default;
		RegistryIoTracker(RegistryIoTracker const&) = delete;
		RegistryIoTracker& operator=(RegistryIoTracker const&) = delete;
		~RegistryIoTracker();

		// The session is named "<prefix> <process ID>" (as FileIoTracker's). false on failure, with the error from
		// GetLastError() (ERROR_ACCESS_DENIED when not elevated)
		bool Start(PCWSTR sessionPrefix);
		void Stop();
		[[nodiscard]] bool IsRunning() const;
		// FILETIME; 0 if it isn't running
		[[nodiscard]] int64_t GetStartTime() const;

		// every process and key with operations in the last minute, the counts since the key was first seen
		[[nodiscard]] std::vector<RegistryIoCounters> GetKeys() const;
		// operations waiting for their keys' names
		[[nodiscard]] size_t GetDeferredCount() const;
		// the events the session dropped (its buffers full: more operations than the tracker kept up with), and the
		// real-time buffers lost; 0 if it isn't running
		[[nodiscard]] uint64_t GetLostEvents() const;
		// forgets a process that exited, as its ID may be reused
		void RemoveProcess(uint32_t pid);

	private:
		static void WINAPI OnEvent(_EVENT_RECORD* record);
		static DWORD WINAPI ProcessThread(void* param);
		static DWORD WINAPI ResolverThread(void* param);
		// on the resolver's thread: names the key objects operations wait on, from the handle table
		void Resolve();

		std::wstring m_SessionName;
		uint64_t m_Session{ 0 }, m_Trace{ 0 };	// TRACEHANDLE (session control) and PROCESSTRACE_HANDLE (consumer)
		wil::unique_handle m_hThread, m_hResolver;
		// nothrow: the app (with exceptions) includes this header too
		wil::unique_event_nothrow m_Stop;
		mutable wil::srwlock m_Lock;
		RegistryIoTable m_Table;
		int64_t m_StartTime{ 0 };
	};
}
