#pragma once

#include <type_traits>

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>

//
// Handles of a process, object type names and object names.
//

namespace WinSys {
	struct HandleEntry {
		uint64_t Value;
		void* Object;		// the kernel object's address; null when it isn't known (see HandleEnumerator)
		uint32_t Access;	// granted access
		uint32_t Attributes;	// OBJ_INHERIT, OBJ_PROTECT_CLOSE (HANDLE_FLAG_* are different)
		uint16_t TypeIndex;	// see ObjectTypes
	};

	struct ObjectTypes final abstract {
		// the type's name ("File", "Process"...), from NtQueryObject(ObjectTypesInformation), cached; empty if unknown
		[[nodiscard]] static std::wstring const& GetName(uint16_t typeIndex);
	};

	//
	// A process's handles. Two sources:
	//  - The process itself (NtQueryInformationProcess, ProcessHandleInformation): cheap, but no object addresses.
	//    Needs the process opened with query access.
	//  - The system's handle table (NtQuerySystemInformation, SystemExtendedHandleInformation): has the object
	//    addresses (zeroed by the system when not elevated), but holds every handle in the system, so it costs much
	//    more. The buffer is kept between calls.
	//
	class HandleEnumerator {
	public:
		// nothing if the process can't be queried
		[[nodiscard]] static std::optional<std::vector<HandleEntry>> EnumProcessHandles(uint32_t pid);
		[[nodiscard]] std::optional<std::vector<HandleEntry>> EnumProcessHandlesWithAddresses(uint32_t pid);

	private:
		std::unique_ptr<uint8_t[]> m_Buffer;
		size_t m_Size{ 0 };
	};

	//
	// Object names, queried on a worker thread with a timeout: a name query on a file opened for synchronous I/O waits
	// for the I/O in progress on it (a pipe being read, for one), possibly forever. A worker that times out is
	// abandoned (it ends by itself if its query ever returns) and another takes over; it isn't terminated.
	//
	class ObjectNameQuery {
	public:
		ObjectNameQuery();
		~ObjectNameQuery();
		ObjectNameQuery(ObjectNameQuery const&) = delete;
		ObjectNameQuery& operator=(ObjectNameQuery const&) = delete;

		// the name of the object a handle in this process refers to; nothing on a timeout. An object without
		// a name gives an empty string. The NT name: a file is \Device\HarddiskVolume3\..., a key \REGISTRY\...
		std::optional<std::wstring> GetName(HANDLE handle, uint32_t timeoutMs = 100);
		// workers that timed out and are still blocked
		[[nodiscard]] int GetAbandonedCount() const;

	private:
		struct Worker;
		std::shared_ptr<Worker> m_Worker;
		int m_Abandoned{ 0 };
	};

	//
	// NT device paths (\Device\HarddiskVolume3\...) to drive letters, from a table read when it's constructed (unlike
	// Helpers::GetDosNameFromNtName, whose shared table is built without a lock: this is safe on any thread)
	//
	class DosNames {
	public:
		DosNames();
		// the name itself if no drive maps it
		[[nodiscard]] std::wstring Convert(std::wstring const& ntName) const;

	private:
		std::vector<std::pair<std::wstring, std::wstring>> m_Devices;	// "\Device\HarddiskVolume3\", "C:\"
	};

	// a process's image name by ID, for HandleNames::QueryName: a non-owning reference to any callable (a lambda), valid
	// for the call it's passed to. Not std::function, whose bad_function_call (an exception class) WinSys can't define:
	// it builds without exceptions, which changes their classes' layout, and an app linking both gets a C4743 mismatch
	class ProcessNameLookup {
	public:
		ProcessNameLookup() noexcept = default;
		template<typename F> requires (!std::is_same_v<std::remove_cvref_t<F>, ProcessNameLookup>)
		ProcessNameLookup(F const& f) noexcept : m_Callable(&f),
			m_Invoke([](void const* callable, DWORD pid) -> std::wstring { return (*static_cast<F const*>(callable))(pid); }) {}

		explicit operator bool() const noexcept {
			return m_Invoke != nullptr;
		}
		std::wstring operator()(DWORD pid) const {
			return m_Invoke(m_Callable, pid);
		}

	private:
		void const* m_Callable{ nullptr };
		std::wstring(*m_Invoke)(void const*, DWORD) { nullptr };
	};

	//
	// Readable names for the objects of another process's handles, and closing them. Safe on any thread.
	//
	struct HandleNames final abstract {
		// \REGISTRY\MACHINE\... and \REGISTRY\USER\<SID>\... as the registry editor shows them (HKLM\..., HKCU\..., HKU\...)
		[[nodiscard]] static std::wstring RegistryName(std::wstring ntName);

		// the name of a handle's object in another process (hProcess has PROCESS_DUP_HANDLE): processes and threads by ID
		// and image name (processName: the image name of a process ID, or empty), tokens by user and logon session,
		// files as DOS paths, keys as HKLM\...; other objects by their names. File names are queried through nameQuery
		// (a file's query can hang) and only if queryFiles; the rest directly. Empty if it has no name or can't be queried
		[[nodiscard]] static std::wstring QueryName(HANDLE hProcess, HandleEntry const& entry, ObjectNameQuery& nameQuery,
			DosNames const& dosNames, ProcessNameLookup processName, bool queryFiles = true);

		// closes the handle in its process (hProcess has PROCESS_DUP_HANDLE), if it still refers to an object of the
		// type (the value may have been closed and reused since it was listed): false with ERROR_INVALID_HANDLE if not,
		// or with the close's last error
		static bool CloseInProcess(HANDLE hProcess, uint64_t value, std::wstring const& type);
	};
}
