#pragma once

#include <stdint.h>
#include <algorithm>

#ifdef WINSYS_NAMESPACE
namespace WinSys {
#endif
	struct ProcessOrThreadKey {
		int64_t Created;
		uint32_t Id;

		bool operator==(const ProcessOrThreadKey& other) const {
			return other.Created == Created && other.Id == Id;
		}
	};

	struct HandleKey {
		uint32_t ProcessId;
		uint32_t Handle;
		size_t Object;

		HandleKey(uint32_t pid, uint32_t handle, size_t obj) : ProcessId(pid), Handle(handle), Object(obj) {}
		HandleKey() {}

		bool operator==(const HandleKey& other) const {
			return other.Handle == Handle && other.ProcessId == ProcessId && Object == other.Object;
		}
	};

template<>
struct ::std::hash<ProcessOrThreadKey> {
	size_t operator()(const ProcessOrThreadKey& key) const {
		return key.Created ^ key.Id;
	}
};

template<>
struct ::std::hash<HandleKey> {
	size_t operator()(const HandleKey& key) const {
		return key.Handle ^ key.ProcessId ^ key.Object;
	}
};
