#pragma once

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
}
