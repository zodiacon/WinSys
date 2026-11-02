#include "pch.h"
#include "UnloadedModules.h"
#include <wil/resource.h>
#include <algorithm>

namespace WinSys {
	std::vector<UnloadedModule> UnloadedModules::Parse(void const* trace, size_t elementSize, size_t count) {
		std::vector<UnloadedModule> modules;
		if (!trace || elementSize < sizeof(RTL_UNLOAD_EVENT_TRACE))
			return modules;
		for (size_t i = 0; i < count; i++) {
			auto& entry = *reinterpret_cast<RTL_UNLOAD_EVENT_TRACE const*>((BYTE const*)trace + i * elementSize);
			if (!entry.BaseAddress)
				continue;
			UnloadedModule m;
			m.BaseAddress = (uint64_t)entry.BaseAddress;
			m.Size = entry.SizeOfImage;
			m.Sequence = entry.Sequence;
			m.TimeDateStamp = entry.TimeDateStamp;
			m.CheckSum = entry.CheckSum;
			// the high and low DWORDs of VS_FIXEDFILEINFO's product version (msftedit.dll: 10.0.29698.1000, its file
			// version 6.2.29698.1000)
			m.Version = (uint64_t(entry.Version[0]) << 32) | entry.Version[1];
			m.Name.assign(entry.ImageName, ::wcsnlen(entry.ImageName, _countof(entry.ImageName)));
			modules.push_back(std::move(m));
		}
		std::sort(modules.begin(), modules.end(), [](auto& a, auto& b) { return a.Sequence > b.Sequence; });
		return modules;
	}

	std::optional<std::vector<UnloadedModule>> UnloadedModules::Query(uint32_t pid) {
		PULONG elementSize = nullptr, elementCount = nullptr;
		PVOID eventTrace = nullptr;
		::RtlGetUnloadEventTraceEx(&elementSize, &elementCount, &eventTrace);
		if (!elementSize || !elementCount || !eventTrace) {
			::SetLastError(ERROR_NOT_SUPPORTED);
			return {};
		}
		wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
		if (!hProcess)
			return {};

		// ntdll's variables, at the same addresses in the target
		ULONG size = 0, count = 0;
		PVOID array = nullptr;
		if (!::ReadProcessMemory(hProcess.get(), elementSize, &size, sizeof(size), nullptr)
			|| !::ReadProcessMemory(hProcess.get(), elementCount, &count, sizeof(count), nullptr)
			|| !::ReadProcessMemory(hProcess.get(), eventTrace, &array, sizeof(array), nullptr))
			return {};
		// no DLL unloaded yet: the array isn't allocated
		if (!array || count == 0)
			return std::vector<UnloadedModule>{};
		if (size < sizeof(RTL_UNLOAD_EVENT_TRACE) || size > 0x1000 || count > 0x4000) {
			::SetLastError(ERROR_INVALID_DATA);
			return {};
		}
		std::vector<BYTE> buffer(size_t(size) * count);
		if (!::ReadProcessMemory(hProcess.get(), array, buffer.data(), buffer.size(), nullptr))
			return {};
		return Parse(buffer.data(), size, count);
	}
}
