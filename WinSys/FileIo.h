#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <wil/resource.h>

//
// File I/O per process and file, counted from an ETW real-time session on the Microsoft-Windows-Kernel-File provider
// (its read and write events; administrator rights needed, as for ProcessNetworkTracker). The process is the one the
// I/O was issued in: the system's for the cache manager's lazy writes and paging I/O. A file is known by its file key
// (the file system's per-stream context, the same for every open of the file), named from the provider's events
// (NameCreate for the key, Create for the file object a read or write then uses); a file opened before the session
// started gets its name from a handle to its file object, looked up in the system's handle table on a thread of the
// tracker's own (every 2 seconds while some are unnamed), else stays unnamed. A file with no I/O for a minute is
// forgotten. The events arrive on a background thread about once a second.
//

struct _EVENT_RECORD;	// evntcons.h

namespace WinSys {
	class DosNames;	// Handles.h
	class ObjectNameQuery;

	struct FileIoCounters {
		uint32_t Pid{ 0 };
		uint64_t FileKey{ 0 };
		std::wstring Name;	// a DOS path where a drive maps it, else the NT name; empty if not known (yet)
		uint64_t BytesRead{ 0 }, BytesWritten{ 0 };
		uint64_t Reads{ 0 }, Writes{ 0 };
		int64_t FirstSeen{ 0 }, LastSeen{ 0 };	// FILETIME: the file's first and last I/O by the process
	};

	class FileIoTracker {
	public:
		FileIoTracker() = default;
		FileIoTracker(FileIoTracker const&) = delete;
		FileIoTracker& operator=(FileIoTracker const&) = delete;
		~FileIoTracker();

		// The session is named "<prefix> <process ID>" (as ProcessNetworkTracker's). false on failure, with the error
		// from GetLastError() (ERROR_ACCESS_DENIED when not elevated)
		bool Start(PCWSTR sessionPrefix);
		void Stop();
		[[nodiscard]] bool IsRunning() const;
		// FILETIME; 0 if it isn't running
		[[nodiscard]] int64_t GetStartTime() const;

		// every process and file with I/O in the last minute, the counts since the file was first seen
		[[nodiscard]] std::vector<FileIoCounters> GetFiles() const;
		// forgets a process that exited, as its ID may be reused
		void RemoveProcess(uint32_t pid);

	private:
		struct FileId {
			uint32_t Pid;
			uint64_t Key;
			bool operator==(FileId const&) const = default;
		};
		struct FileIdHash {
			size_t operator()(FileId const& id) const noexcept {
				return std::hash<uint64_t>()(id.Key) ^ (std::hash<uint32_t>()(id.Pid) << 1);
			}
		};
		struct File {
			uint64_t BytesRead{ 0 }, BytesWritten{ 0 }, Reads{ 0 }, Writes{ 0 };
			int64_t FirstSeen{ 0 }, LastSeen{ 0 };
			ULONGLONG LastTick{ 0 };
		};
		struct Name {
			std::wstring Text;
			ULONGLONG Tick{ 0 };	// when it was learned or last used
		};

		static void WINAPI OnEvent(_EVENT_RECORD* record);
		void OnReadWrite(uint64_t fileObject, uint64_t fileKey, uint32_t pid, uint32_t size, bool write);
		static DWORD WINAPI ProcessThread(void* param);
		static DWORD WINAPI ResolverThread(void* param);
		// on the resolver's thread: names the files waiting for one from the handle table
		void Resolve(ObjectNameQuery& nameQuery);
		// forgets idle files, and names and file objects no longer used
		void Prune();

		std::wstring m_SessionName;
		uint64_t m_Session{ 0 }, m_Trace{ 0 };	// TRACEHANDLE (session control) and PROCESSTRACE_HANDLE (consumer)
		wil::unique_handle m_hThread, m_hResolver;
		// nothrow: the app (with exceptions) includes this header too, and the throwing wil::unique_event exists only there
		wil::unique_event_nothrow m_Stop;
		mutable wil::srwlock m_Lock;
		std::unordered_map<FileId, File, FileIdHash> m_Files;
		std::unordered_map<uint64_t, Name> m_Names;		// by file key: NT names (or DOS ones, from a handle)
		std::unordered_map<uint64_t, Name> m_ObjectNames;	// by file object, from Create events
		std::unordered_map<uint64_t, uint64_t> m_Pending;	// file keys without a name, to the file object last used
		std::unordered_map<uint64_t, int> m_Attempts;		// file keys the resolver looked for, and how often
		std::shared_ptr<DosNames const> m_DosNames;	// rebuilt now and then, as drives come and go
		int64_t m_StartTime{ 0 };
	};
}
