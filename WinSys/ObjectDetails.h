#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "Enums.h"

//
// The details of the object a handle refers to, in this or another process: its counts, its type's statistics, the
// state particular to its type (an event's, a mutex's owner, a section's size, a file's position...), and its
// security descriptor, read and written whole (for the ACL editor).
//

namespace WinSys {
	struct ObjectTypeStatistics {
		uint32_t Objects{ 0 }, Handles{ 0 };
		uint32_t PeakObjects{ 0 }, PeakHandles{ 0 };
		uint32_t ValidAccessMask{ 0 };
		GENERIC_MAPPING GenericMapping{};
		uint32_t PoolType{ 0 };	// POOL_TYPE: 0 nonpaged, 1 paged, 0x200 nonpaged NX
		bool SecurityRequired{ false };
	};

	struct EventDetails {
		bool Notification{ false };	// a manual-reset event; else auto-reset (synchronization)
		bool Signaled{ false };
	};

	struct MutantDetails {
		int32_t CurrentCount{ 0 };	// 1: free; 0 or less: owned (recursively when below 0)
		bool Abandoned{ false };
		// the owning thread (MutantOwnerInformation); zero when free or not known
		uint32_t OwnerProcessId{ 0 }, OwnerThreadId{ 0 };
	};

	struct SemaphoreDetails {
		int32_t Count{ 0 }, Maximum{ 0 };
	};

	struct TimerDetails {
		bool Signaled{ false };
		int64_t Remaining{ 0 };	// 100 ns units until it's due; negative once it's past
	};

	struct IoCompletionDetails {
		int32_t Depth{ 0 };	// queued completions
	};

	struct SectionDetails {
		uint64_t Size{ 0 };
		uint32_t Attributes{ 0 };	// SEC_IMAGE, SEC_FILE, SEC_COMMIT...
		// SEC_IMAGE (SectionImageInformation)
		bool Image{ false };
		uint64_t EntryPoint{ 0 };	// at the image's preferred base
		uint16_t Machine{ 0 };	// IMAGE_FILE_MACHINE_*
		uint16_t Subsystem{ 0 };	// IMAGE_SUBSYSTEM_*
		uint32_t ImageFileSize{ 0 };
	};

	struct PipeDetails {
		uint32_t Type{ 0 };	// FILE_PIPE_BYTE_STREAM_TYPE (0) or FILE_PIPE_MESSAGE_TYPE (1)
		uint32_t Configuration{ 0 };	// FILE_PIPE_INBOUND (0), OUTBOUND (1), FULL_DUPLEX (2)
		uint32_t MaximumInstances{ 0 };	// 0xFFFFFFFF: unlimited
		uint32_t CurrentInstances{ 0 };
		uint32_t InboundQuota{ 0 }, ReadDataAvailable{ 0 };
		uint32_t OutboundQuota{ 0 }, WriteQuotaAvailable{ 0 };
		uint32_t State{ 0 };	// FILE_PIPE_DISCONNECTED_STATE (1), LISTENING (2), CONNECTED (3), CLOSING (4)
		uint32_t End{ 0 };	// FILE_PIPE_CLIENT_END (0) or FILE_PIPE_SERVER_END (1)
	};

	struct FileDetails {
		bool TimedOut{ false };	// the queries blocked (a synchronous file with I/O in progress): nothing else is known
		std::optional<uint32_t> DeviceType;	// FILE_DEVICE_*
		uint32_t DeviceCharacteristics{ 0 };	// FILE_REMOVABLE_MEDIA, FILE_REMOTE_DEVICE...
		std::optional<uint32_t> Mode;	// FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, FILE_DELETE_ON_CLOSE...
		std::optional<uint64_t> Size, Allocation;
		std::optional<uint64_t> Position;	// meaningful for synchronous I/O only
		bool Directory{ false }, DeletePending{ false };
		uint32_t Links{ 0 };
		std::optional<PipeDetails> Pipe;	// a named pipe's local end
	};

	struct KeyDetails {
		int64_t LastWriteTime{ 0 };	// FILETIME units
		std::optional<uint32_t> SubKeys, Values;	// need KEY_QUERY_VALUE
	};

	struct SymbolicLinkDetails {
		std::wstring Target;
	};

	struct ProcessDetails {
		uint32_t Id{ 0 };
		std::wstring ImagePath;
		int64_t CreateTime{ 0 };
		std::optional<uint32_t> ExitCode;	// it has exited
	};

	struct ThreadDetails {
		uint32_t Id{ 0 }, ProcessId{ 0 };
		int64_t CreateTime{ 0 };
		std::optional<uint32_t> ExitCode;	// it has exited
	};

	struct TokenDetails {
		std::wstring User, UserSid;
		LUID LogonSession{};
		uint32_t SessionId{ 0 };
		bool Primary{ true };
		SECURITY_IMPERSONATION_LEVEL ImpersonationLevel{ SecurityAnonymous };	// an impersonation token's
		IntegrityLevel Integrity{ IntegrityLevel::Error };
		bool Elevated{ false };
	};

	struct JobDetails {
		std::wstring Name;
		uint32_t ActiveProcesses{ 0 }, TotalProcesses{ 0 }, TerminatedProcesses{ 0 };
	};

	struct ObjectDetails {
		std::wstring TypeName;
		uint32_t GrantedAccess{ 0 };
		uint32_t Attributes{ 0 };	// OBJ_INHERIT, OBJ_PERMANENT, OBJ_EXCLUSIVE...
		// without the duplicate the query made. Since Windows 8.1 (on 64-bit), a handle takes references in batches of
		// 32,768 in advance, which its uses consume, so References is only an estimate: up to 32,768 per handle, plus
		// the references taken otherwise
		uint32_t Handles{ 0 }, References{ 0 };
		uint32_t PagedPoolCharge{ 0 }, NonPagedPoolCharge{ 0 };
		int64_t CreationTime{ 0 };	// a symbolic link's; zero for other types
		ObjectTypeStatistics TypeStatistics;

		// the type's own; each only for its type, and only if the handle's access allows the query
		std::optional<EventDetails> Event;
		std::optional<MutantDetails> Mutant;
		std::optional<SemaphoreDetails> Semaphore;
		std::optional<TimerDetails> Timer;
		std::optional<IoCompletionDetails> IoCompletion;
		std::optional<SectionDetails> Section;
		std::optional<FileDetails> File;
		std::optional<KeyDetails> Key;
		std::optional<SymbolicLinkDetails> SymbolicLink;
		std::optional<ProcessDetails> Process;
		std::optional<ThreadDetails> Thread;
		std::optional<TokenDetails> Token;
		std::optional<JobDetails> Job;
	};

	struct ObjectInspector final {
		// the object a handle in a process refers to (hProcess has PROCESS_DUP_HANDLE), through a duplicate with the
		// handle's access, which limits what can be queried. type: the type the handle was listed with, as the value may
		// have been closed and reused since: nullopt with ERROR_INVALID_HANDLE if it isn't that type's anymore, or with
		// the duplication's error. A file's queries can block (as its name's: see ObjectNameQuery), so they run on a
		// thread that's abandoned after fileTimeoutMs
		[[nodiscard]] static std::optional<ObjectDetails> QueryHandle(HANDLE hProcess, uint64_t value, std::wstring const& type,
			uint32_t fileTimeoutMs = 500);
		// the statistics and generic mapping of an object's type (any handle; no access needed), and its name; nothing on failure
		[[nodiscard]] static std::optional<ObjectTypeStatistics> QueryTypeStatistics(HANDLE h, std::wstring* typeName = nullptr);
		// a duplicate of a handle in a process (hProcess has PROCESS_DUP_HANDLE) with the handle's access, if it still refers
		// to an object of the type; the caller closes it. Null with ERROR_INVALID_HANDLE if the value isn't that type's
		// anymore, or with the duplication's error
		[[nodiscard]] static HANDLE OpenHandle(HANDLE hProcess, uint64_t value, std::wstring const& type);
		// an object's security descriptor (self-relative), the parts asked for: OWNER_SECURITY_INFORMATION and the others
		// need READ_CONTROL, SACL_SECURITY_INFORMATION ACCESS_SYSTEM_SECURITY. Empty (with the last error) on failure
		[[nodiscard]] static std::vector<BYTE> GetSecurity(HANDLE h, SECURITY_INFORMATION info);
		// sets parts of an object's security descriptor: the DACL needs WRITE_DAC, the owner WRITE_OWNER. false (with the
		// last error) on failure
		static bool SetSecurity(HANDLE h, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd);
		// "Disk", "Named Pipe", "Network File System"... ; empty if not known
		[[nodiscard]] static PCWSTR DeviceTypeToString(uint32_t type);
	};
}
