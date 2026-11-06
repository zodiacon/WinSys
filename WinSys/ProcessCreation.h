#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <wil/resource.h>
#include "Keys.h"

struct _EVENT_RECORD;	// evntcons.h

//
// Who created each process, from Microsoft-Windows-Kernel-Process's ProcessStart events (a real-time ETW session;
// administrator rights). The event is logged in the creating thread's context, so its header's process is the creator,
// while its payload's ParentProcessID is the parent the new process got: the creator itself, unless the creator passed
// another (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), which is how a parent is spoofed. Windows does that too, on someone's
// behalf: the Application Information service (Appinfo) for an elevation, Secondary Logon (seclogon) for Run As; the
// creator's being one of those is recorded with the event. Only processes created while the session runs are known.
//
// The exits (ProcessStop, event 2) are recorded too, with their exit times and codes: a process that lived between
// two snapshots of the system is known only from these (TakeExited, the History recorder's). The events' image names
// and the stops' fields are read by name (TDH), as their layouts differ between versions.
//
namespace WinSys {
	enum class ProcessCreator : uint8_t {
		Parent,		// the parent created it
		OnBehalf,	// a Windows service created it for the parent (elevation, Run As)
		Other,		// another process created it, giving it another parent: a spoofed parent
	};

	struct ProcessCreation {
		uint32_t Pid{ 0 };
		int64_t CreateTime{ 0 };	// FILETIME, as the process's own
		uint32_t ParentPid{ 0 };	// the parent it got
		uint32_t CreatorPid{ 0 }, CreatorTid{ 0 };	// who created it
		ProcessCreator Creator{ ProcessCreator::Parent };
		std::wstring CreatorService;	// OnBehalf: "Appinfo" or "seclogon"
		std::wstring CreatorName;		// the creator's image name, when it isn't the parent (read as the event arrives)
		std::wstring ImagePath;			// the start's (an NT path, "\Device\HarddiskVolume3\..."), else the stop's file name
		bool Started{ false };			// its start was seen (else only its stop: it ran before the session)
		int64_t ExitTime{ 0 };			// FILETIME; 0 while it runs
		std::optional<uint32_t> ExitCode;
		bool Taken{ false };			// TakeExited returned it

		[[nodiscard]] ProcessOrThreadKey Key() const {
			return { CreateTime, Pid };
		}
	};

	struct ProcessCreationParser final {
		// ProcessStart's (event 1's) payload, its first fields: ProcessID (UInt32), CreateTime (FILETIME), ParentProcessID
		// (UInt32); from version 3 a ProcessSequenceNumber (UInt64) follows the ID, and ParentProcessID comes right after
		// CreateTime still. Nothing for another event or a short payload
		[[nodiscard]] static std::optional<ProcessCreation> Parse(uint16_t id, uint8_t version, void const* data, size_t size);
		// a creation's kind from its creator and parent: the creator's services name Appinfo or seclogon (service names
		// compared without case) for OnBehalf
		[[nodiscard]] static ProcessCreator Classify(uint32_t creatorPid, uint32_t parentPid, std::wstring const& creatorService);
		// "created by svchost.exe (1234), on behalf of the parent" and the like; empty for Parent
		[[nodiscard]] static std::wstring Describe(ProcessCreation const& creation);
	};

	class ProcessCreationTracker {
	public:
		ProcessCreationTracker() = default;
		ProcessCreationTracker(ProcessCreationTracker const&) = delete;
		ProcessCreationTracker& operator=(ProcessCreationTracker const&) = delete;
		~ProcessCreationTracker();

		// the session "<sessionPrefix> <pid>"; false (the last error set: ERROR_ACCESS_DENIED when not elevated) if it can't start
		bool Start(PCWSTR sessionPrefix);
		void Stop();
		[[nodiscard]] bool IsRunning() const;
		// FILETIME: processes created before weren't seen
		[[nodiscard]] int64_t GetStartTime() const;

		[[nodiscard]] std::optional<ProcessCreation> Get(ProcessOrThreadKey const& key) const;
		// the creations whose creator isn't their parent (OnBehalf and Other), for the processes still known
		[[nodiscard]] std::vector<ProcessCreation> GetMismatches() const;
		// a process that exited: its ID may be reused
		void Remove(ProcessOrThreadKey const& key);
		// the processes that exited since the last call (each once), whose starts were seen; the exited ones are kept for
		// ExitedKept after they exit, taken or not
		[[nodiscard]] std::vector<ProcessCreation> TakeExited();
		static constexpr int64_t ExitedKept = 10LL * 60 * 10000000;	// 10 minutes

	private:
		static void WINAPI OnEvent(_EVENT_RECORD* record);
		static DWORD WINAPI ProcessThread(void* param);

		std::wstring m_SessionName;
		uint64_t m_Session{ 0 }, m_Trace{ 0 };	// TRACEHANDLE and PROCESSTRACE_HANDLE
		wil::unique_handle m_hThread;
		mutable wil::srwlock m_Lock;
		std::unordered_map<ProcessOrThreadKey, ProcessCreation> m_Creations;
		int64_t m_StartTime{ 0 };
	};
}
