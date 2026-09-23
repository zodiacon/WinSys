#include "pch.h"
#include "SystemInfo.h"
#include <algorithm>

using namespace WinSys;

namespace {
	thread_local NTSTATUS LastStatus;

	constexpr size_t MaxBufferSize = 1 << 30;
	// limit when the kernel does not report the required size
	constexpr size_t MaxGuessedBufferSize = 1 << 24;

	bool IsBufferTooSmall(NTSTATUS status) {
		return status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW;
	}

	// Next buffer size after a "too small" failure, or 0 to give up. Keeps the size a multiple of elementSize.
	size_t GrowBuffer(size_t current, ULONG required, size_t elementSize) {
		auto size = required > current ? size_t(required) + required / 8 : current * 2;
		if (size > (required > current ? MaxBufferSize : MaxGuessedBufferSize))
			return 0;
		return (size + elementSize - 1) / elementSize * elementSize;
	}

	//
	// Queries a variable-size class, growing the buffer until the data fits.
	// The returned buffer is trimmed to the returned length.
	// Some classes require the buffer size to be a multiple of their element size.
	//
	std::optional<std::vector<BYTE>> Query(SYSTEM_INFORMATION_CLASS cls, ULONG initialSize = 1 << 12, const void* input = nullptr, ULONG inputSize = 0, size_t elementSize = 1) {
		std::vector<BYTE> buffer(initialSize);
		for (;;) {
			ULONG len = 0;
			LastStatus = input
				? ::NtQuerySystemInformationEx(cls, const_cast<void*>(input), inputSize, buffer.data(), (ULONG)buffer.size(), &len)
				: ::NtQuerySystemInformation(cls, buffer.data(), (ULONG)buffer.size(), &len);
			if (NT_SUCCESS(LastStatus)) {
				if (len < buffer.size())
					buffer.resize(len);
				return buffer;
			}
			if (!IsBufferTooSmall(LastStatus))
				return {};
			auto size = GrowBuffer(buffer.size(), len, elementSize);
			if (size == 0)
				return {};
			buffer.resize(size);
		}
	}

	std::optional<std::vector<BYTE>> QueryGroup(SYSTEM_INFORMATION_CLASS cls, std::optional<USHORT> group, ULONG initialSize = 1 << 12, size_t elementSize = 1) {
		return group ? Query(cls, initialSize, &*group, sizeof(USHORT), elementSize) : Query(cls, initialSize, nullptr, 0, elementSize);
	}

	//
	// Queries a fixed-size class. 'value' may carry input fields.
	// If the kernel expects a larger (newer) structure, the known prefix is returned.
	//
	template<typename T>
	std::optional<T> QueryFixed(SYSTEM_INFORMATION_CLASS cls, T value = {}) {
		ULONG len = 0;
		LastStatus = ::NtQuerySystemInformation(cls, &value, sizeof(value), &len);
		if (NT_SUCCESS(LastStatus))
			return value;
		if (!IsBufferTooSmall(LastStatus) || len <= sizeof(T))
			return {};

		std::vector<BYTE> buffer(len);
		memcpy(buffer.data(), &value, sizeof(T));
		LastStatus = ::NtQuerySystemInformation(cls, buffer.data(), len, &len);
		if (!NT_SUCCESS(LastStatus))
			return {};
		memcpy(&value, buffer.data(), sizeof(T));
		return value;
	}

	template<typename T, typename TInput>
	std::optional<T> QueryFixedEx(SYSTEM_INFORMATION_CLASS cls, TInput const& input) {
		T value{};
		LastStatus = ::NtQuerySystemInformationEx(cls, const_cast<TInput*>(&input), sizeof(input), &value, sizeof(value), nullptr);
		if (!NT_SUCCESS(LastStatus))
			return {};
		return value;
	}

	// Copies up to 'count' elements starting at 'first', never reading past the end of 'buffer'
	template<typename T>
	std::vector<T> ToVector(std::vector<BYTE> const& buffer, const void* first, size_t count) {
		auto start = static_cast<const BYTE*>(first);
		auto end = buffer.data() + buffer.size();
		if (start < buffer.data() || start >= end)
			return {};
		count = std::min(count, size_t(end - start) / sizeof(T));
		auto p = reinterpret_cast<const T*>(start);
		return std::vector<T>(p, p + count);
	}

	// The whole buffer as an array
	template<typename T>
	std::vector<T> ToVector(std::optional<std::vector<BYTE>> const& buffer) {
		if (!buffer)
			return {};
		return ToVector<T>(*buffer, buffer->data(), buffer->size() / sizeof(T));
	}

	// Queries a class that returns a plain array of T (per processor, if a group is specified)
	template<typename T>
	std::vector<T> QueryArray(SYSTEM_INFORMATION_CLASS cls, std::optional<USHORT> group = {}) {
		return ToVector<T>(QueryGroup(cls, group, sizeof(T) * 256, sizeof(T)));
	}

	bool IsInside(std::vector<BYTE> const& buffer, const void* p, size_t size) {
		auto b = static_cast<const BYTE*>(p);
		return b >= buffer.data() && b + size <= buffer.data() + buffer.size();
	}

	std::wstring ToString(UNICODE_STRING const& str) {
		return str.Buffer ? std::wstring(str.Buffer, str.Length / sizeof(WCHAR)) : std::wstring();
	}

	template<size_t N>
	std::string ToString(const UCHAR(&str)[N]) {
		auto s = reinterpret_cast<const char*>(str);
		return std::string(s, strnlen(s, N));
	}

	template<size_t N>
	std::wstring ToString(const WCHAR(&str)[N]) {
		return std::wstring(str, wcsnlen(str, N));
	}

	std::wstring QueryString(SYSTEM_INFORMATION_CLASS cls) {
		auto buffer = Query(cls, 1 << 10);
		if (!buffer || buffer->size() < sizeof(UNICODE_STRING))
			return L"";
		return ToString(*reinterpret_cast<const UNICODE_STRING*>(buffer->data()));
	}

	std::vector<SystemInfo::Process> ParseProcesses(std::vector<BYTE> const& buffer, bool extendedThreads, bool extension) {
		std::vector<SystemInfo::Process> processes;
		auto p = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(buffer.data());
		while (IsInside(buffer, p, FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads))) {
			auto& process = processes.emplace_back();
			memcpy(&process.Info, p, FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads));
			process.ImageName = ToString(p->ImageName);
			process.Info.ImageName = {};
			process.Info.NextEntryOffset = 0;

			auto threads = reinterpret_cast<const BYTE*>(p) + FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads);
			if (extendedThreads) {
				process.Threads = ToVector<SYSTEM_EXTENDED_THREAD_INFORMATION>(buffer, threads, p->NumberOfThreads);
			}
			else {
				for (auto& t : ToVector<SYSTEM_THREAD_INFORMATION>(buffer, threads, p->NumberOfThreads))
					process.Threads.emplace_back().ThreadInfo = t;
			}

			if (extension && p->UniqueProcessId) {
				auto ext = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION_EXTENSION*>(threads + sizeof(SYSTEM_EXTENDED_THREAD_INFORMATION) * p->NumberOfThreads);
				if (IsInside(buffer, ext, sizeof(*ext))) {
					process.Extension = *ext;
					auto base = reinterpret_cast<const BYTE*>(ext);
					if (ext->PackageFullNameOffset)
						process.PackageFullName = reinterpret_cast<PCWSTR>(base + ext->PackageFullNameOffset);
					if (ext->AppIdOffset)
						process.AppId = reinterpret_cast<PCWSTR>(base + ext->AppIdOffset);
					if (ext->UserSidOffset) {
						PWSTR sid;
						if (::ConvertSidToStringSid((PSID)(base + ext->UserSidOffset), &sid)) {
							process.UserSid = sid;
							::LocalFree(sid);
						}
					}
				}
			}
			if (p->NextEntryOffset == 0)
				break;
			p = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const BYTE*>(p) + p->NextEntryOffset);
		}
		return processes;
	}

	std::vector<SystemInfo::Process> QueryProcesses(SYSTEM_INFORMATION_CLASS cls, bool extendedThreads, bool extension) {
		auto buffer = Query(cls, 1 << 20);
		return buffer ? ParseProcesses(*buffer, extendedThreads, extension) : std::vector<SystemInfo::Process>();
	}

	std::vector<SystemInfo::PageFile> QueryPageFiles(SYSTEM_INFORMATION_CLASS cls, bool ex) {
		std::vector<SystemInfo::PageFile> files;
		auto buffer = Query(cls, 1 << 10);
		if (!buffer)
			return files;
		auto p = buffer->data();
		auto size = ex ? sizeof(SYSTEM_PAGEFILE_INFORMATION_EX) : sizeof(SYSTEM_PAGEFILE_INFORMATION);
		while (IsInside(*buffer, p, size)) {
			auto& file = files.emplace_back();
			memcpy(&file.Info, p, size);
			file.Name = ToString(file.Info.PageFileName);
			file.Info.PageFileName = {};
			auto next = file.Info.NextEntryOffset;
			file.Info.NextEntryOffset = 0;
			if (next == 0)
				break;
			p += next;
		}
		return files;
	}

	std::vector<SystemInfo::SessionPoolTags> QuerySessionPoolTags(SYSTEM_INFORMATION_CLASS cls) {
		std::vector<SystemInfo::SessionPoolTags> sessions;
		auto buffer = Query(cls, 1 << 16);
		if (!buffer)
			return sessions;
		auto p = reinterpret_cast<const SYSTEM_SESSION_POOLTAG_INFORMATION*>(buffer->data());
		while (IsInside(*buffer, p, FIELD_OFFSET(SYSTEM_SESSION_POOLTAG_INFORMATION, TagInfo))) {
			sessions.push_back({ p->SessionId, ToVector<SYSTEM_POOLTAG>(*buffer, p->TagInfo, p->Count) });
			if (p->NextEntryOffset == 0)
				break;
			p = reinterpret_cast<const SYSTEM_SESSION_POOLTAG_INFORMATION*>(reinterpret_cast<const BYTE*>(p) + p->NextEntryOffset);
		}
		return sessions;
	}

	SystemInfo::ModuleEx ToModuleEx(RTL_PROCESS_MODULE_INFORMATION_EX const& info) {
		SystemInfo::ModuleEx module{ info };
		module.FullPath = ToString(info.BaseInfo.FullPathName);
		if (info.BaseInfo.OffsetToFileName < module.FullPath.size())
			module.FileName = module.FullPath.substr(info.BaseInfo.OffsetToFileName);
		return module;
	}

	std::vector<SystemInfo::LogicalProcessorRelationship> ParseRelationships(std::optional<std::vector<BYTE>> const& buffer) {
		std::vector<SystemInfo::LogicalProcessorRelationship> relationships;
		if (!buffer)
			return relationships;
		auto p = buffer->data();
		while (IsInside(*buffer, p, FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor))) {
			auto info = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(p);
			if (info->Size == 0 || !IsInside(*buffer, p, info->Size))
				break;
			auto& r = relationships.emplace_back();
			r.Relationship = info->Relationship;
			switch (info->Relationship) {
				case RelationProcessorCore:
				case RelationProcessorPackage:
				case RelationProcessorDie:
				case RelationProcessorModule:
					r.Flags = info->Processor.Flags;
					r.EfficiencyClass = info->Processor.EfficiencyClass;
					r.GroupMasks = ToVector<GROUP_AFFINITY>(*buffer, info->Processor.GroupMask, info->Processor.GroupCount);
					break;

				case RelationNumaNode:
				case RelationNumaNodeEx:
					r.NodeNumber = info->NumaNode.NodeNumber;
					// GroupCount is zero on systems predating multi-group support
					r.GroupMasks = ToVector<GROUP_AFFINITY>(*buffer, info->NumaNode.GroupMasks, std::max<WORD>(1, info->NumaNode.GroupCount));
					break;

				case RelationCache:
					r.CacheLevel = info->Cache.Level;
					r.Associativity = info->Cache.Associativity;
					r.LineSize = info->Cache.LineSize;
					r.CacheSize = info->Cache.CacheSize;
					r.CacheType = info->Cache.Type;
					r.GroupMasks = ToVector<GROUP_AFFINITY>(*buffer, info->Cache.GroupMasks, std::max<WORD>(1, info->Cache.GroupCount));
					break;

				case RelationGroup:
					r.MaximumGroupCount = info->Group.MaximumGroupCount;
					r.Groups = ToVector<PROCESSOR_GROUP_INFO>(*buffer, info->Group.GroupInfo, info->Group.ActiveGroupCount);
					break;
			}
			p += info->Size;
		}
		return relationships;
	}

	std::vector<SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION> QueryArchitectures(SYSTEM_INFORMATION_CLASS cls, HANDLE hProcess) {
		auto buffer = Query(cls, 1 << 8, &hProcess, sizeof(hProcess));
		auto items = ToVector<SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION>(buffer);
		// the list is terminated by a zero entry
		auto end = std::find_if(items.begin(), items.end(), [](auto& item) { return item.Machine == 0; });
		items.erase(end, items.end());
		return items;
	}

	std::optional<SystemInfo::CpuSetList> QueryCpuSetList(SYSTEM_INFORMATION_CLASS cls) {
		auto buffer = Query(cls, 1 << 8);
		if (!buffer || buffer->size() < sizeof(ULONGLONG))
			return {};
		auto data = reinterpret_cast<const ULONGLONG*>(buffer->data());
		return SystemInfo::CpuSetList{ data[0], ToVector<ULONGLONG>(*buffer, data + 1, buffer->size() / sizeof(ULONGLONG) - 1) };
	}

	std::optional<SystemInfo::TimeZone> QueryTimeZone(SYSTEM_INFORMATION_CLASS cls) {
		auto info = QueryFixed<RTL_TIME_ZONE_INFORMATION>(cls);
		if (!info)
			return {};
		return SystemInfo::TimeZone{ *info, ToString(info->StandardName), ToString(info->DaylightName) };
	}
}

NTSTATUS SystemInfo::GetLastStatus() noexcept {
	return LastStatus;
}

std::optional<SYSTEM_BASIC_INFORMATION> SystemInfo::GetBasicInformation() {
	return QueryFixed<SYSTEM_BASIC_INFORMATION>(SystemBasicInformation);
}

std::optional<SYSTEM_PROCESSOR_INFORMATION> SystemInfo::GetProcessorInformation() {
	return QueryFixed<SYSTEM_PROCESSOR_INFORMATION>(SystemProcessorInformation);
}

std::optional<SYSTEM_PERFORMANCE_INFORMATION> SystemInfo::GetPerformanceInformation() {
	return QueryFixed<SYSTEM_PERFORMANCE_INFORMATION>(SystemPerformanceInformation);
}

std::optional<SYSTEM_TIMEOFDAY_INFORMATION> SystemInfo::GetTimeOfDayInformation() {
	return QueryFixed<SYSTEM_TIMEOFDAY_INFORMATION>(SystemTimeOfDayInformation);
}

std::vector<SystemInfo::Process> SystemInfo::GetProcessInformation() {
	return QueryProcesses(SystemProcessInformation, false, false);
}

std::vector<ULONG> SystemInfo::GetCallCountInformation() {
	auto buffer = Query(SystemCallCountInformation);
	if (!buffer || buffer->size() < sizeof(SYSTEM_CALL_COUNT_INFORMATION))
		return {};
	return ToVector<ULONG>(*buffer, buffer->data() + sizeof(SYSTEM_CALL_COUNT_INFORMATION), buffer->size());
}

std::optional<SYSTEM_DEVICE_INFORMATION> SystemInfo::GetDeviceInformation() {
	return QueryFixed<SYSTEM_DEVICE_INFORMATION>(SystemDeviceInformation);
}

std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> SystemInfo::GetProcessorPerformanceInformation(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>(SystemProcessorPerformanceInformation, group);
}

std::optional<SYSTEM_FLAGS_INFORMATION> SystemInfo::GetFlagsInformation() {
	return QueryFixed<SYSTEM_FLAGS_INFORMATION>(SystemFlagsInformation);
}

std::vector<SystemInfo::Module> SystemInfo::GetKernelModuleInformation() {
	std::vector<Module> modules;
	auto buffer = Query(SystemModuleInformation, 1 << 16);
	if (!buffer || buffer->size() < sizeof(ULONG))
		return modules;
	auto info = reinterpret_cast<const RTL_PROCESS_MODULES*>(buffer->data());
	for (auto& m : ToVector<RTL_PROCESS_MODULE_INFORMATION>(*buffer, info->Modules, info->NumberOfModules)) {
		auto& module = modules.emplace_back(Module{ m, ToString(m.FullPathName) });
		if (m.OffsetToFileName < module.FullPath.size())
			module.FileName = module.FullPath.substr(m.OffsetToFileName);
	}
	return modules;
}

std::vector<RTL_PROCESS_LOCK_INFORMATION> SystemInfo::GetLocksInformation() {
	auto buffer = Query(SystemLocksInformation, 1 << 16);
	if (!buffer || buffer->size() < sizeof(ULONG))
		return {};
	auto info = reinterpret_cast<const RTL_PROCESS_LOCKS*>(buffer->data());
	return ToVector<RTL_PROCESS_LOCK_INFORMATION>(*buffer, info->Locks, info->NumberOfLocks);
}

std::optional<SystemInfo::StackTraceInformation> SystemInfo::GetStackTraceInformation() {
	auto buffer = Query(SystemStackTraceInformation, 1 << 16);
	if (!buffer || buffer->size() < FIELD_OFFSET(RTL_PROCESS_BACKTRACES, BackTraces))
		return {};
	auto info = reinterpret_cast<const RTL_PROCESS_BACKTRACES*>(buffer->data());
	StackTraceInformation traces{ info->CommittedMemory, info->ReservedMemory, info->NumberOfBackTraceLookups };
	for (auto& bt : ToVector<RTL_PROCESS_BACKTRACE_INFORMATION>(*buffer, info->BackTraces, info->NumberOfBackTraces)) {
		auto depth = std::min<size_t>(bt.Depth, _countof(bt.BackTrace));
		traces.BackTraces.push_back({ bt.TraceCount, bt.Index, std::vector<void*>(bt.BackTrace, bt.BackTrace + depth) });
	}
	return traces;
}

std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> SystemInfo::GetHandleInformation() {
	auto buffer = Query(SystemHandleInformation, 1 << 20);
	if (!buffer || buffer->size() < sizeof(ULONG))
		return {};
	auto info = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION*>(buffer->data());
	return ToVector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(*buffer, info->Handles, info->NumberOfHandles);
}

std::vector<SystemInfo::ObjectType> SystemInfo::GetObjectInformation() {
	std::vector<ObjectType> types;
	auto buffer = Query(SystemObjectInformation, 1 << 20);
	if (!buffer)
		return types;
	// entry offsets are relative to the start of the buffer
	auto base = buffer->data();
	auto type = reinterpret_cast<const SYSTEM_OBJECTTYPE_INFORMATION*>(base);
	while (IsInside(*buffer, type, sizeof(*type))) {
		auto& t = types.emplace_back(ObjectType{ *type, ToString(type->TypeName) });
		t.Info.TypeName = {};
		t.Info.NextEntryOffset = 0;
		if (type->NumberOfObjects && type->TypeName.Buffer) {
			// objects follow the type name
			auto object = reinterpret_cast<const SYSTEM_OBJECT_INFORMATION*>((const BYTE*)type->TypeName.Buffer + type->TypeName.MaximumLength);
			while (IsInside(*buffer, object, sizeof(*object))) {
				auto& o = t.Objects.emplace_back(Object{ *object, ToString(object->NameInfo) });
				o.Info.NameInfo = {};
				o.Info.NextEntryOffset = 0;
				if (object->NextEntryOffset == 0)
					break;
				object = reinterpret_cast<const SYSTEM_OBJECT_INFORMATION*>(base + object->NextEntryOffset);
			}
		}
		if (type->NextEntryOffset == 0)
			break;
		type = reinterpret_cast<const SYSTEM_OBJECTTYPE_INFORMATION*>(base + type->NextEntryOffset);
	}
	return types;
}

std::vector<SystemInfo::PageFile> SystemInfo::GetPageFileInformation() {
	return QueryPageFiles(SystemPageFileInformation, false);
}

std::optional<SYSTEM_VDM_INSTEMUL_INFO> SystemInfo::GetVdmInstemulInformation() {
	return QueryFixed<SYSTEM_VDM_INSTEMUL_INFO>(SystemVdmInstemulInformation);
}

std::optional<SYSTEM_FILECACHE_INFORMATION> SystemInfo::GetFileCacheInformation() {
	return QueryFixed<SYSTEM_FILECACHE_INFORMATION>(SystemFileCacheInformation);
}

std::vector<SYSTEM_POOLTAG> SystemInfo::GetPoolTagInformation() {
	auto buffer = Query(SystemPoolTagInformation, 1 << 18);
	if (!buffer || buffer->size() < sizeof(ULONG))
		return {};
	auto info = reinterpret_cast<const SYSTEM_POOLTAG_INFORMATION*>(buffer->data());
	return ToVector<SYSTEM_POOLTAG>(*buffer, info->TagInfo, info->Count);
}

std::vector<SYSTEM_INTERRUPT_INFORMATION> SystemInfo::GetInterruptInformation(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_INTERRUPT_INFORMATION>(SystemInterruptInformation, group);
}

std::optional<SYSTEM_DPC_BEHAVIOR_INFORMATION> SystemInfo::GetDpcBehaviorInformation() {
	return QueryFixed<SYSTEM_DPC_BEHAVIOR_INFORMATION>(SystemDpcBehaviorInformation);
}

std::optional<SYSTEM_QUERY_TIME_ADJUST_INFORMATION> SystemInfo::GetTimeAdjustmentInformation() {
	return QueryFixed<SYSTEM_QUERY_TIME_ADJUST_INFORMATION>(SystemTimeAdjustmentInformation);
}

std::optional<SYSTEM_EXCEPTION_INFORMATION> SystemInfo::GetSystemExceptionInformation() {
	return QueryFixed<SYSTEM_EXCEPTION_INFORMATION>(SystemExceptionInformation);
}

std::optional<SYSTEM_KERNEL_DEBUGGER_INFORMATION> SystemInfo::GetKernelDebuggerInformation() {
	return QueryFixed<SYSTEM_KERNEL_DEBUGGER_INFORMATION>(SystemKernelDebuggerInformation);
}

std::optional<SYSTEM_CONTEXT_SWITCH_INFORMATION> SystemInfo::GetContextSwitchInformation() {
	return QueryFixed<SYSTEM_CONTEXT_SWITCH_INFORMATION>(SystemContextSwitchInformation);
}

std::optional<SYSTEM_REGISTRY_QUOTA_INFORMATION> SystemInfo::GetRegistryQuotaInformation() {
	return QueryFixed<SYSTEM_REGISTRY_QUOTA_INFORMATION>(SystemRegistryQuotaInformation);
}

std::vector<SYSTEM_PROCESSOR_IDLE_INFORMATION> SystemInfo::GetProcessorIdleInformation(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_PROCESSOR_IDLE_INFORMATION>(SystemProcessorIdleInformation, group);
}

std::optional<SystemInfo::LegacyDriverInformation> SystemInfo::GetLegacyDriverInformation() {
	auto buffer = Query(SystemLegacyDriverInformation, sizeof(SYSTEM_LEGACY_DRIVER_INFORMATION));
	if (!buffer || buffer->size() < sizeof(SYSTEM_LEGACY_DRIVER_INFORMATION))
		return {};
	LegacyDriverInformation info{ *reinterpret_cast<const SYSTEM_LEGACY_DRIVER_INFORMATION*>(buffer->data()) };
	info.VetoList = ToString(info.Info.VetoList);
	info.Info.VetoList = {};
	return info;
}

std::optional<SystemInfo::TimeZone> SystemInfo::GetCurrentTimeZoneInformation() {
	return QueryTimeZone(SystemCurrentTimeZoneInformation);
}

std::vector<SYSTEM_LOOKASIDE_INFORMATION> SystemInfo::GetLookasideInformation() {
	return QueryArray<SYSTEM_LOOKASIDE_INFORMATION>(SystemLookasideInformation);
}

std::optional<SYSTEM_RANGE_START_INFORMATION> SystemInfo::GetRangeStartInformation() {
	return QueryFixed<SYSTEM_RANGE_START_INFORMATION>(SystemRangeStartInformation);
}

std::vector<SystemInfo::Verifier> SystemInfo::GetVerifierInformation() {
	std::vector<Verifier> drivers;
	auto buffer = Query(SystemVerifierInformation, 1 << 12);
	if (!buffer)
		return drivers;
	auto p = buffer->data();
	while (IsInside(*buffer, p, sizeof(SYSTEM_VERIFIER_INFORMATION))) {
		auto info = reinterpret_cast<const SYSTEM_VERIFIER_INFORMATION*>(p);
		auto& driver = drivers.emplace_back(Verifier{ *info, ToString(info->DriverName) });
		driver.Info.DriverName = {};
		driver.Info.NextEntryOffset = 0;
		if (info->NextEntryOffset == 0)
			break;
		p += info->NextEntryOffset;
	}
	return drivers;
}

std::vector<SystemInfo::Process> SystemInfo::GetSessionProcessInformation(ULONG sessionId) {
	std::vector<BYTE> buffer(1 << 18);
	for (;;) {
		SYSTEM_SESSION_PROCESS_INFORMATION info{ sessionId, (ULONG)buffer.size(), buffer.data() };
		ULONG len = 0;
		LastStatus = ::NtQuerySystemInformation(SystemSessionProcessInformation, &info, sizeof(info), &len);
		if (NT_SUCCESS(LastStatus)) {
			if (len && len < buffer.size())
				buffer.resize(len);
			return ParseProcesses(buffer, false, false);
		}
		auto size = IsBufferTooSmall(LastStatus) ? GrowBuffer(buffer.size(), len, 1) : 0;
		if (size == 0)
			return {};
		buffer.resize(size);
	}
}

std::optional<SYSTEM_NUMA_INFORMATION> SystemInfo::GetNumaProcessorMap() {
	return QueryFixed<SYSTEM_NUMA_INFORMATION>(SystemNumaProcessorMap);
}

std::vector<SystemInfo::Process> SystemInfo::GetExtendedProcessInformation() {
	return QueryProcesses(SystemExtendedProcessInformation, true, false);
}

std::optional<ULONG> SystemInfo::GetRecommendedSharedDataAlignment() {
	return QueryFixed<ULONG>(SystemRecommendedSharedDataAlignment);
}

std::optional<ULONG> SystemInfo::GetComPlusPackage() {
	return QueryFixed<ULONG>(SystemComPlusPackage);
}

std::optional<SYSTEM_NUMA_INFORMATION> SystemInfo::GetNumaAvailableMemory() {
	return QueryFixed<SYSTEM_NUMA_INFORMATION>(SystemNumaAvailableMemory);
}

std::vector<SYSTEM_PROCESSOR_POWER_INFORMATION> SystemInfo::GetProcessorPowerInformation(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_PROCESSOR_POWER_INFORMATION>(SystemProcessorPowerInformation, group);
}

std::optional<SYSTEM_BASIC_INFORMATION> SystemInfo::GetEmulationBasicInformation() {
	return QueryFixed<SYSTEM_BASIC_INFORMATION>(SystemEmulationBasicInformation);
}

std::optional<SYSTEM_PROCESSOR_INFORMATION> SystemInfo::GetEmulationProcessorInformation() {
	return QueryFixed<SYSTEM_PROCESSOR_INFORMATION>(SystemEmulationProcessorInformation);
}

std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> SystemInfo::GetExtendedHandleInformation() {
	auto buffer = Query(SystemExtendedHandleInformation, 1 << 20);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles))
		return {};
	auto info = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX*>(buffer->data());
	return ToVector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(*buffer, info->Handles, info->NumberOfHandles);
}

std::optional<ULONG> SystemInfo::GetLostDelayedWriteInformation() {
	return QueryFixed<ULONG>(SystemLostDelayedWriteInformation);
}

std::vector<SYSTEM_BIGPOOL_ENTRY> SystemInfo::GetBigPoolInformation() {
	auto buffer = Query(SystemBigPoolInformation, 1 << 20);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_BIGPOOL_INFORMATION, AllocatedInfo))
		return {};
	auto info = reinterpret_cast<const SYSTEM_BIGPOOL_INFORMATION*>(buffer->data());
	return ToVector<SYSTEM_BIGPOOL_ENTRY>(*buffer, info->AllocatedInfo, info->Count);
}

std::vector<SystemInfo::SessionPoolTags> SystemInfo::GetSessionPoolTagInformation() {
	return QuerySessionPoolTags(SystemSessionPoolTagInformation);
}

std::vector<SYSTEM_SESSION_MAPPED_VIEW_INFORMATION> SystemInfo::GetSessionMappedViewInformation() {
	std::vector<SYSTEM_SESSION_MAPPED_VIEW_INFORMATION> sessions;
	auto buffer = Query(SystemSessionMappedViewInformation, 1 << 10);
	if (!buffer)
		return sessions;
	auto p = buffer->data();
	while (IsInside(*buffer, p, sizeof(SYSTEM_SESSION_MAPPED_VIEW_INFORMATION))) {
		auto& session = sessions.emplace_back(*reinterpret_cast<const SYSTEM_SESSION_MAPPED_VIEW_INFORMATION*>(p));
		auto next = session.NextEntryOffset;
		session.NextEntryOffset = 0;
		if (next == 0)
			break;
		p += next;
	}
	return sessions;
}

std::optional<ULONG> SystemInfo::GetObjectSecurityMode() {
	return QueryFixed<ULONG>(SystemObjectSecurityMode);
}

std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> SystemInfo::GetLogicalProcessorInformation(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>(SystemLogicalProcessorInformation, group);
}

std::vector<BYTE> SystemInfo::GetFirmwareTableInformation(ULONG providerSignature, SYSTEM_FIRMWARE_TABLE_ACTION action, ULONG tableId) {
	ULONG tableSize = 1 << 12;
	for (;;) {
		std::vector<BYTE> buffer(FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer) + tableSize);
		auto info = reinterpret_cast<SYSTEM_FIRMWARE_TABLE_INFORMATION*>(buffer.data());
		info->ProviderSignature = providerSignature;
		info->Action = action;
		info->TableID = tableId;
		info->TableBufferLength = tableSize;
		LastStatus = ::NtQuerySystemInformation(SystemFirmwareTableInformation, info, (ULONG)buffer.size(), nullptr);
		if (NT_SUCCESS(LastStatus))
			return std::vector<BYTE>(info->TableBuffer, info->TableBuffer + std::min(info->TableBufferLength, tableSize));
		// on STATUS_BUFFER_TOO_SMALL, TableBufferLength holds the required size
		if (LastStatus != STATUS_BUFFER_TOO_SMALL || info->TableBufferLength <= tableSize)
			return {};
		tableSize = info->TableBufferLength;
	}
}

std::vector<SystemInfo::ModuleEx> SystemInfo::GetKernelModuleInformationEx() {
	std::vector<ModuleEx> modules;
	auto buffer = Query(SystemModuleInformationEx, 1 << 16);
	if (!buffer)
		return modules;
	auto p = buffer->data();
	while (IsInside(*buffer, p, sizeof(RTL_PROCESS_MODULE_INFORMATION_EX))) {
		auto info = reinterpret_cast<const RTL_PROCESS_MODULE_INFORMATION_EX*>(p);
		// the last entry is an empty terminator
		if (info->NextOffset == 0 && info->BaseInfo.FullPathName[0] == 0)
			break;
		modules.push_back(ToModuleEx(*info));
		modules.back().Info.NextOffset = 0;
		if (info->NextOffset == 0)
			break;
		p += info->NextOffset;
	}
	return modules;
}

std::optional<SYSTEM_MEMORY_LIST_INFORMATION> SystemInfo::GetMemoryListInformation() {
	return QueryFixed<SYSTEM_MEMORY_LIST_INFORMATION>(SystemMemoryListInformation);
}

std::optional<SYSTEM_FILECACHE_INFORMATION> SystemInfo::GetFileCacheInformationEx() {
	return QueryFixed<SYSTEM_FILECACHE_INFORMATION>(SystemFileCacheInformationEx);
}

std::vector<SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION> SystemInfo::GetProcessorIdleCycleTimeInformation(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION>(SystemProcessorIdleCycleTimeInformation, group);
}

std::optional<SYSTEM_VERIFIER_CANCELLATION_INFORMATION> SystemInfo::GetVerifierCancellationInformation() {
	return QueryFixed<SYSTEM_VERIFIER_CANCELLATION_INFORMATION>(SystemVerifierCancellationInformation);
}

std::optional<SystemInfo::RefTrace> SystemInfo::GetRefTraceInformation() {
	auto buffer = Query(SystemRefTraceInformation, sizeof(SYSTEM_REF_TRACE_INFORMATION));
	if (!buffer || buffer->size() < sizeof(SYSTEM_REF_TRACE_INFORMATION))
		return {};
	auto info = reinterpret_cast<const SYSTEM_REF_TRACE_INFORMATION*>(buffer->data());
	RefTrace trace{ *info, ToString(info->TraceProcessName), ToString(info->TracePoolTags) };
	trace.Info.TraceProcessName = {};
	trace.Info.TracePoolTags = {};
	return trace;
}

std::optional<SYSTEM_SPECIAL_POOL_INFORMATION> SystemInfo::GetSpecialPoolInformation() {
	return QueryFixed<SYSTEM_SPECIAL_POOL_INFORMATION>(SystemSpecialPoolInformation);
}

std::wstring SystemInfo::GetProcessIdInformation(ULONG pid) {
	std::vector<WCHAR> name(MAX_PATH);
	for (;;) {
		SYSTEM_PROCESS_ID_INFORMATION info{ ULongToHandle(pid) };
		info.ImageName.MaximumLength = USHORT(name.size() * sizeof(WCHAR));
		info.ImageName.Buffer = name.data();
		LastStatus = ::NtQuerySystemInformation(SystemProcessIdInformation, &info, sizeof(info), nullptr);
		if (NT_SUCCESS(LastStatus))
			return ToString(info.ImageName);
		// on STATUS_INFO_LENGTH_MISMATCH, MaximumLength holds the required size
		if (LastStatus != STATUS_INFO_LENGTH_MISMATCH || info.ImageName.MaximumLength <= name.size() * sizeof(WCHAR))
			return L"";
		name.resize(info.ImageName.MaximumLength / sizeof(WCHAR));
	}
}

std::optional<SYSTEM_BOOT_ENVIRONMENT_INFORMATION> SystemInfo::GetBootEnvironmentInformation() {
	return QueryFixed<SYSTEM_BOOT_ENVIRONMENT_INFORMATION>(SystemBootEnvironmentInformation);
}

std::optional<SYSTEM_HYPERVISOR_QUERY_INFORMATION> SystemInfo::GetHypervisorInformation() {
	return QueryFixed<SYSTEM_HYPERVISOR_QUERY_INFORMATION>(SystemHypervisorInformation);
}

std::optional<SystemInfo::VerifierEx> SystemInfo::GetVerifierInformationEx() {
	auto buffer = Query(SystemVerifierInformationEx, sizeof(SYSTEM_VERIFIER_INFORMATION_EX));
	if (!buffer || buffer->size() < sizeof(SYSTEM_VERIFIER_INFORMATION_EX))
		return {};
	auto info = reinterpret_cast<const SYSTEM_VERIFIER_INFORMATION_EX*>(buffer->data());
	VerifierEx verifier{ *info, ToString(info->PreviousBucketName) };
	verifier.Info.PreviousBucketName = {};
	return verifier;
}

std::optional<SystemInfo::TimeZone> SystemInfo::GetTimeZoneInformation() {
	return QueryTimeZone(SystemTimeZoneInformation);
}

std::optional<SYSTEM_PREFETCH_PATCH_INFORMATION> SystemInfo::GetPrefetchPatchInformation() {
	return QueryFixed<SYSTEM_PREFETCH_PATCH_INFORMATION>(SystemPrefetchPatchInformation);
}

std::wstring SystemInfo::GetSystemPartitionInformation() {
	return QueryString(SystemSystemPartitionInformation);
}

std::wstring SystemInfo::GetSystemDiskInformation() {
	return QueryString(SystemSystemDiskInformation);
}

std::vector<SystemInfo::ProcessorPerformanceStates> SystemInfo::GetProcessorPerformanceDistribution(std::optional<USHORT> group) {
	std::vector<ProcessorPerformanceStates> processors;
	auto buffer = QueryGroup(SystemProcessorPerformanceDistribution, group);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION, Offsets))
		return processors;
	auto info = reinterpret_cast<const SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION*>(buffer->data());
	// each offset (relative to the start of the buffer) points to a processor's state distribution
	for (auto offset : ToVector<ULONG>(*buffer, info->Offsets, info->ProcessorCount)) {
		auto dist = reinterpret_cast<const SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION*>(buffer->data() + offset);
		if (!IsInside(*buffer, dist, FIELD_OFFSET(SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION, States)))
			break;
		processors.push_back({ dist->ProcessorNumber, ToVector<SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT>(*buffer, dist->States, dist->StateCount) });
	}
	return processors;
}

std::optional<USHORT> SystemInfo::GetNumaProximityNodeInformation(ULONG nodeProximityId) {
	auto map = QueryFixed<SYSTEM_NUMA_PROXIMITY_MAP>(SystemNumaProximityNodeInformation, { nodeProximityId });
	if (!map)
		return {};
	return map->NodeNumber;
}

std::optional<SystemInfo::DynamicTimeZone> SystemInfo::GetDynamicTimeZoneInformation() {
	// same layout as RTL_DYNAMIC_TIME_ZONE_INFORMATION
	auto info = QueryFixed<DYNAMIC_TIME_ZONE_INFORMATION>(SystemDynamicTimeZoneInformation);
	if (!info)
		return {};
	return DynamicTimeZone{ *info, ToString(info->StandardName), ToString(info->DaylightName), ToString(info->TimeZoneKeyName) };
}

std::optional<SYSTEM_CODEINTEGRITY_INFORMATION> SystemInfo::GetCodeIntegrityInformation() {
	return QueryFixed<SYSTEM_CODEINTEGRITY_INFORMATION>(SystemCodeIntegrityInformation, { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) });
}

std::string SystemInfo::GetProcessorBrandString() {
	auto buffer = Query(SystemProcessorBrandString, 64);
	if (!buffer)
		return "";
	auto str = reinterpret_cast<const char*>(buffer->data());
	return std::string(str, strnlen(str, buffer->size()));
}

std::vector<SYSTEM_VA_LIST_INFORMATION> SystemInfo::GetVirtualAddressInformation() {
	return QueryArray<SYSTEM_VA_LIST_INFORMATION>(SystemVirtualAddressInformation);
}

std::vector<SystemInfo::LogicalProcessorRelationship> SystemInfo::GetLogicalProcessorAndGroupInformation(LOGICAL_PROCESSOR_RELATIONSHIP relationship) {
	return ParseRelationships(Query(SystemLogicalProcessorAndGroupInformation, 1 << 14, &relationship, sizeof(relationship)));
}

std::vector<SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION> SystemInfo::GetProcessorCycleTimeInformation(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION>(SystemProcessorCycleTimeInformation, group);
}

std::optional<SystemInfo::VhdBootInformation> SystemInfo::GetVhdBootInformation() {
	auto buffer = Query(SystemVhdBootInformation, 1 << 10);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_VHD_BOOT_INFORMATION, OsVhdParentVolume))
		return {};
	VhdBootInformation info{};
	memcpy(&info.Info, buffer->data(), std::min(buffer->size(), sizeof(info.Info)));
	auto volume = reinterpret_cast<const WCHAR*>(buffer->data() + FIELD_OFFSET(SYSTEM_VHD_BOOT_INFORMATION, OsVhdParentVolume));
	info.OsVhdParentVolume.assign(volume, wcsnlen(volume, (buffer->size() - FIELD_OFFSET(SYSTEM_VHD_BOOT_INFORMATION, OsVhdParentVolume)) / sizeof(WCHAR)));
	return info;
}

std::vector<PS_CPU_QUOTA_QUERY_ENTRY> SystemInfo::GetCpuQuotaInformation() {
	auto buffer = Query(SystemCpuQuotaInformation, 1 << 10);
	if (!buffer || buffer->size() < FIELD_OFFSET(PS_CPU_QUOTA_QUERY_INFORMATION, SessionInformation))
		return {};
	auto info = reinterpret_cast<const PS_CPU_QUOTA_QUERY_INFORMATION*>(buffer->data());
	return ToVector<PS_CPU_QUOTA_QUERY_ENTRY>(*buffer, info->SessionInformation, info->SessionCount);
}

std::optional<SYSTEM_BASIC_INFORMATION> SystemInfo::GetNativeBasicInformation() {
	return QueryFixed<SYSTEM_BASIC_INFORMATION>(SystemNativeBasicInformation);
}

std::optional<SYSTEM_ERROR_PORT_TIMEOUTS> SystemInfo::GetErrorPortTimeouts() {
	return QueryFixed<SYSTEM_ERROR_PORT_TIMEOUTS>(SystemErrorPortTimeouts);
}

std::optional<SYSTEM_LOW_PRIORITY_IO_INFORMATION> SystemInfo::GetLowPriorityIoInformation() {
	return QueryFixed<SYSTEM_LOW_PRIORITY_IO_INFORMATION>(SystemLowPriorityIoInformation);
}

std::optional<BOOT_ENTROPY_NT_RESULT> SystemInfo::GetTpmBootEntropyInformation() {
	return QueryFixed<BOOT_ENTROPY_NT_RESULT>(SystemTpmBootEntropyInformation);
}

std::optional<SYSTEM_VERIFIER_COUNTERS_INFORMATION> SystemInfo::GetVerifierCountersInformation() {
	auto info = QueryFixed<SYSTEM_VERIFIER_COUNTERS_INFORMATION>(SystemVerifierCountersInformation);
	if (info)
		info->Legacy.DriverName = {};
	return info;
}

std::optional<SYSTEM_FILECACHE_INFORMATION> SystemInfo::GetPagedPoolInformationEx() {
	return QueryFixed<SYSTEM_FILECACHE_INFORMATION>(SystemPagedPoolInformationEx);
}

std::optional<SYSTEM_FILECACHE_INFORMATION> SystemInfo::GetSystemPtesInformationEx() {
	return QueryFixed<SYSTEM_FILECACHE_INFORMATION>(SystemSystemPtesInformationEx);
}

std::vector<USHORT> SystemInfo::GetNodeDistanceInformation(USHORT node) {
	return ToVector<USHORT>(Query(SystemNodeDistanceInformation, 1 << 10, &node, sizeof(node), sizeof(USHORT)));
}

std::optional<SYSTEM_ACPI_AUDIT_INFORMATION> SystemInfo::GetAcpiAuditInformation() {
	return QueryFixed<SYSTEM_ACPI_AUDIT_INFORMATION>(SystemAcpiAuditInformation);
}

std::optional<SYSTEM_BASIC_PERFORMANCE_INFORMATION> SystemInfo::GetBasicPerformanceInformation() {
	return QueryFixed<SYSTEM_BASIC_PERFORMANCE_INFORMATION>(SystemBasicPerformanceInformation);
}

std::optional<SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION> SystemInfo::GetQueryPerformanceCounterInformation() {
	return QueryFixed<SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION>(SystemQueryPerformanceCounterInformation);
}

std::vector<SystemInfo::SessionPoolTags> SystemInfo::GetSessionBigPoolInformation() {
	return QuerySessionPoolTags(SystemSessionBigPoolInformation);
}

std::vector<SYSTEM_BAD_PAGE_INFORMATION> SystemInfo::GetBadPageInformation() {
	return QueryArray<SYSTEM_BAD_PAGE_INFORMATION>(SystemBadPageInformation);
}

std::optional<SYSTEM_CONSOLE_INFORMATION> SystemInfo::GetConsoleInformation() {
	return QueryFixed<SYSTEM_CONSOLE_INFORMATION>(SystemConsoleInformation);
}

std::optional<SYSTEM_PLATFORM_BINARY_INFORMATION> SystemInfo::GetPlatformBinaryInformation() {
	return QueryFixed<SYSTEM_PLATFORM_BINARY_INFORMATION>(SystemPlatformBinaryInformation);
}

std::optional<SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION> SystemInfo::GetHypervisorProcessorCountInformation() {
	return QueryFixed<SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION>(SystemHypervisorProcessorCountInformation);
}

std::optional<SystemInfo::MemoryTopology> SystemInfo::GetMemoryTopologyInformation() {
	auto buffer = Query(SystemMemoryTopologyInformation, 1 << 12);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_MEMORY_TOPOLOGY_INFORMATION, Run))
		return {};
	auto info = reinterpret_cast<const SYSTEM_MEMORY_TOPOLOGY_INFORMATION*>(buffer->data());
	return MemoryTopology{ info->NumberOfNodes, info->NumberOfChannels, ToVector<PHYSICAL_CHANNEL_RUN>(*buffer, info->Run, (size_t)info->NumberOfRuns) };
}

std::optional<SYSTEM_MEMORY_CHANNEL_INFORMATION> SystemInfo::GetMemoryChannelInformation(ULONG channel) {
	return QueryFixed<SYSTEM_MEMORY_CHANNEL_INFORMATION>(SystemMemoryChannelInformation, { channel });
}

std::optional<SystemInfo::BootLogo> SystemInfo::GetBootLogoInformation() {
	auto buffer = Query(SystemBootLogoInformation, 1 << 16);
	if (!buffer || buffer->size() < sizeof(SYSTEM_BOOT_LOGO_INFORMATION))
		return {};
	auto info = reinterpret_cast<const SYSTEM_BOOT_LOGO_INFORMATION*>(buffer->data());
	BootLogo logo{ info->Flags };
	if (info->BitmapOffset >= sizeof(*info) && info->BitmapOffset < buffer->size())
		logo.Bitmap.assign(buffer->begin() + info->BitmapOffset, buffer->end());
	return logo;
}

std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX> SystemInfo::GetProcessorPerformanceInformationEx(std::optional<USHORT> group) {
	return QueryArray<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX>(SystemProcessorPerformanceInformationEx, group);
}

std::optional<SystemInfo::CriticalProcessErrorLog> SystemInfo::GetCriticalProcessErrorLogInformation() {
	auto buffer = Query(SystemCriticalProcessErrorLogInformation, sizeof(CRITICAL_PROCESS_EXCEPTION_DATA));
	if (!buffer || buffer->size() < sizeof(CRITICAL_PROCESS_EXCEPTION_DATA))
		return {};
	auto info = reinterpret_cast<const CRITICAL_PROCESS_EXCEPTION_DATA*>(buffer->data());
	CriticalProcessErrorLog log{ *info, ToString(info->ModuleName) };
	log.Info.ModuleName = {};
	return log;
}

std::optional<SYSTEM_SECUREBOOT_POLICY_INFORMATION> SystemInfo::GetSecureBootPolicyInformation() {
	return QueryFixed<SYSTEM_SECUREBOOT_POLICY_INFORMATION>(SystemSecureBootPolicyInformation);
}

std::vector<SystemInfo::PageFile> SystemInfo::GetPageFileInformationEx() {
	return QueryPageFiles(SystemPageFileInformationEx, true);
}

std::optional<SYSTEM_SECUREBOOT_INFORMATION> SystemInfo::GetSecureBootInformation() {
	return QueryFixed<SYSTEM_SECUREBOOT_INFORMATION>(SystemSecureBootInformation);
}

std::optional<SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION> SystemInfo::GetPortableWorkspaceEfiLauncherInformation() {
	return QueryFixed<SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION>(SystemPortableWorkspaceEfiLauncherInformation);
}

std::vector<SystemInfo::Process> SystemInfo::GetFullProcessInformation() {
	return QueryProcesses(SystemFullProcessInformation, true, true);
}

std::optional<SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX> SystemInfo::GetKernelDebuggerInformationEx() {
	return QueryFixed<SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX>(SystemKernelDebuggerInformationEx);
}

std::optional<ULONG> SystemInfo::GetSoftRebootInformation() {
	return QueryFixed<ULONG>(SystemSoftRebootInformation);
}

std::optional<OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2> SystemInfo::GetOfflineDumpConfigInformation() {
	return QueryFixed<OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2>(SystemOfflineDumpConfigInformation);
}

std::optional<SYSTEM_PROCESSOR_FEATURES_INFORMATION> SystemInfo::GetProcessorFeaturesInformation() {
	return QueryFixed<SYSTEM_PROCESSOR_FEATURES_INFORMATION>(SystemProcessorFeaturesInformation);
}

std::vector<BYTE> SystemInfo::GetEdidInformation() {
	auto info = QueryFixed<SYSTEM_EDID_INFORMATION>(SystemEdidInformation);
	if (!info)
		return {};
	return std::vector<BYTE>(std::begin(info->Edid), std::end(info->Edid));
}

std::optional<SystemInfo::ManufacturingInformation> SystemInfo::GetManufacturingInformation() {
	auto buffer = Query(SystemManufacturingInformation, sizeof(SYSTEM_MANUFACTURING_INFORMATION));
	if (!buffer || buffer->size() < sizeof(SYSTEM_MANUFACTURING_INFORMATION))
		return {};
	auto info = reinterpret_cast<const SYSTEM_MANUFACTURING_INFORMATION*>(buffer->data());
	ManufacturingInformation manufacturing{ *info, ToString(info->ProfileName) };
	manufacturing.Info.ProfileName = {};
	return manufacturing;
}

std::optional<SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION> SystemInfo::GetEnergyEstimationConfigInformation() {
	return QueryFixed<SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION>(SystemEnergyEstimationConfigInformation);
}

std::optional<SYSTEM_HYPERVISOR_DETAIL_INFORMATION> SystemInfo::GetHypervisorDetailInformation() {
	return QueryFixed<SYSTEM_HYPERVISOR_DETAIL_INFORMATION>(SystemHypervisorDetailInformation);
}

std::vector<SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION> SystemInfo::GetProcessorCycleStatsInformation(USHORT group) {
	return QueryArray<SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION>(SystemProcessorCycleStatsInformation, group);
}

std::optional<SYSTEM_TPM_INFORMATION> SystemInfo::GetTrustedPlatformModuleInformation() {
	return QueryFixed<SYSTEM_TPM_INFORMATION>(SystemTrustedPlatformModuleInformation);
}

std::optional<SYSTEM_KERNEL_DEBUGGER_FLAGS> SystemInfo::GetKernelDebuggerFlags() {
	return QueryFixed<SYSTEM_KERNEL_DEBUGGER_FLAGS>(SystemKernelDebuggerFlags);
}

std::optional<SYSTEM_CODEINTEGRITYPOLICY_INFORMATION> SystemInfo::GetCodeIntegrityPolicyInformation() {
	return QueryFixed<SYSTEM_CODEINTEGRITYPOLICY_INFORMATION>(SystemCodeIntegrityPolicyInformation);
}

std::optional<SYSTEM_ISOLATED_USER_MODE_INFORMATION> SystemInfo::GetIsolatedUserModeInformation() {
	return QueryFixed<SYSTEM_ISOLATED_USER_MODE_INFORMATION>(SystemIsolatedUserModeInformation);
}

std::optional<SystemInfo::ModuleEx> SystemInfo::GetSingleModuleInformation(void* address) {
	auto info = QueryFixed<SYSTEM_SINGLE_MODULE_INFORMATION>(SystemSingleModuleInformation, { address });
	if (!info)
		return {};
	return ToModuleEx(info->ExInfo);
}

std::optional<SYSTEM_VSM_PROTECTION_INFORMATION> SystemInfo::GetVsmProtectionInformation() {
	return QueryFixed<SYSTEM_VSM_PROTECTION_INFORMATION>(SystemVsmProtectionInformation);
}

std::optional<SystemInfo::SecureBootPolicyFull> SystemInfo::GetSecureBootPolicyFullInformation() {
	auto buffer = Query(SystemSecureBootPolicyFullInformation, 1 << 12);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION, Policy))
		return {};
	auto info = reinterpret_cast<const SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION*>(buffer->data());
	return SecureBootPolicyFull{ info->PolicyInformation, ToVector<BYTE>(*buffer, info->Policy, info->PolicySize) };
}

std::vector<ULONG_PTR> SystemInfo::GetAffinitizedInterruptProcessorInformation() {
	auto buffer = Query(SystemAffinitizedInterruptProcessorInformation, (ULONG)sizeof(KAFFINITY_EX));
	if (!buffer || buffer->size() < FIELD_OFFSET(KAFFINITY_EX, Bitmap))
		return {};
	auto info = reinterpret_cast<const KAFFINITY_EX*>(buffer->data());
	return ToVector<ULONG_PTR>(*buffer, info->Bitmap, info->Count);
}

std::vector<ULONG> SystemInfo::GetRootSiloInformation() {
	auto buffer = Query(SystemRootSiloInformation, 1 << 10);
	if (!buffer || buffer->size() < sizeof(ULONG))
		return {};
	auto info = reinterpret_cast<const SYSTEM_ROOT_SILO_INFORMATION*>(buffer->data());
	return ToVector<ULONG>(*buffer, info->SiloIdList, info->NumberOfSilos);
}

std::vector<SYSTEM_CPU_SET_INFORMATION> SystemInfo::GetCpuSetInformation(HANDLE hProcess) {
	std::vector<SYSTEM_CPU_SET_INFORMATION> sets;
	auto buffer = Query(SystemCpuSetInformation, 1 << 14, &hProcess, sizeof(hProcess));
	if (!buffer)
		return sets;
	// entries are variable-sized; copy the part this SDK knows about
	auto p = buffer->data();
	while (IsInside(*buffer, p, FIELD_OFFSET(SYSTEM_CPU_SET_INFORMATION, CpuSet))) {
		auto size = reinterpret_cast<const SYSTEM_CPU_SET_INFORMATION*>(p)->Size;
		if (size == 0 || !IsInside(*buffer, p, size))
			break;
		auto& set = sets.emplace_back();
		memcpy(&set, p, std::min<size_t>(size, sizeof(set)));
		p += size;
	}
	return sets;
}

std::optional<SystemInfo::CpuSetList> SystemInfo::GetCpuSetTagInformation() {
	return QueryCpuSetList(SystemCpuSetTagInformation);
}

std::optional<SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION> SystemInfo::GetSecureKernelProfileInformation() {
	return QueryFixed<SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION>(SystemSecureKernelProfileInformation);
}

std::vector<BYTE> SystemInfo::GetCodeIntegrityPlatformManifestInformation() {
	auto buffer = Query(SystemCodeIntegrityPlatformManifestInformation, 1 << 12);
	if (!buffer || buffer->size() < sizeof(ULONG))
		return {};
	auto info = reinterpret_cast<const SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION*>(buffer->data());
	return ToVector<BYTE>(*buffer, info->PlatformManifest, info->PlatformManifestSize);
}

std::optional<SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT> SystemInfo::GetInterruptSteeringInformation(SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT const& input) {
	return QueryFixedEx<SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT>(SystemInterruptSteeringInformation, input);
}

std::vector<SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION> SystemInfo::GetSupportedProcessorArchitectures(HANDLE hProcess) {
	return QueryArchitectures(SystemSupportedProcessorArchitectures, hProcess);
}

std::optional<SYSTEM_MEMORY_USAGE_INFORMATION> SystemInfo::GetMemoryUsageInformation() {
	return QueryFixed<SYSTEM_MEMORY_USAGE_INFORMATION>(SystemMemoryUsageInformation);
}

std::optional<SYSTEM_PHYSICAL_MEMORY_INFORMATION> SystemInfo::GetPhysicalMemoryInformation() {
	return QueryFixed<SYSTEM_PHYSICAL_MEMORY_INFORMATION>(SystemPhysicalMemoryInformation);
}

std::optional<SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION> SystemInfo::GetCodeIntegrityUnlockInformation() {
	return QueryFixed<SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION>(SystemCodeIntegrityUnlockInformation);
}

std::optional<SYSTEM_FLUSH_INFORMATION> SystemInfo::GetFlushInformation() {
	return QueryFixed<SYSTEM_FLUSH_INFORMATION>(SystemFlushInformation);
}

std::vector<ULONG_PTR> SystemInfo::GetProcessorIdleMaskInformation() {
	return QueryArray<ULONG_PTR>(SystemProcessorIdleMaskInformation);
}

std::optional<SYSTEM_WRITE_CONSTRAINT_INFORMATION> SystemInfo::GetWriteConstraintInformation() {
	return QueryFixed<SYSTEM_WRITE_CONSTRAINT_INFORMATION>(SystemWriteConstraintInformation);
}

std::optional<SYSTEM_KERNEL_VA_SHADOW_INFORMATION> SystemInfo::GetKernelVaShadowInformation() {
	return QueryFixed<SYSTEM_KERNEL_VA_SHADOW_INFORMATION>(SystemKernelVaShadowInformation);
}

std::optional<SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION> SystemInfo::GetHypervisorSharedPageInformation() {
	return QueryFixed<SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION>(SystemHypervisorSharedPageInformation);
}

std::wstring SystemInfo::GetFirmwarePartitionInformation() {
	return QueryString(SystemFirmwarePartitionInformation);
}

std::optional<SYSTEM_SPECULATION_CONTROL_INFORMATION> SystemInfo::GetSpeculationControlInformation() {
	return QueryFixed<SYSTEM_SPECULATION_CONTROL_INFORMATION>(SystemSpeculationControlInformation);
}

std::optional<SYSTEM_DMA_GUARD_POLICY_INFORMATION> SystemInfo::GetDmaGuardPolicyInformation() {
	return QueryFixed<SYSTEM_DMA_GUARD_POLICY_INFORMATION>(SystemDmaGuardPolicyInformation);
}

std::vector<BYTE> SystemInfo::GetEnclaveLaunchControlInformation() {
	auto info = QueryFixed<SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION>(SystemEnclaveLaunchControlInformation);
	if (!info)
		return {};
	return std::vector<BYTE>(std::begin(info->EnclaveLaunchSigner), std::end(info->EnclaveLaunchSigner));
}

std::optional<SystemInfo::CpuSetList> SystemInfo::GetWorkloadAllowedCpuSetsInformation() {
	return QueryCpuSetList(SystemWorkloadAllowedCpuSetsInformation);
}

std::optional<SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION> SystemInfo::GetCodeIntegrityUnlockModeInformation() {
	return QueryFixed<SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION>(SystemCodeIntegrityUnlockModeInformation);
}

std::optional<SYSTEM_FLAGS_INFORMATION> SystemInfo::GetFlags2Information() {
	return QueryFixed<SYSTEM_FLAGS_INFORMATION>(SystemFlags2Information);
}

std::optional<SYSTEM_SECURITY_MODEL_INFORMATION> SystemInfo::GetSecurityModelInformation() {
	return QueryFixed<SYSTEM_SECURITY_MODEL_INFORMATION>(SystemSecurityModelInformation);
}

std::optional<SYSTEM_FEATURE_CONFIGURATION_INFORMATION> SystemInfo::GetFeatureConfigurationInformation(RTL_FEATURE_ID featureId, RTL_FEATURE_CONFIGURATION_TYPE type) {
	SYSTEM_FEATURE_CONFIGURATION_QUERY query{ type, featureId };
	return QueryFixedEx<SYSTEM_FEATURE_CONFIGURATION_INFORMATION>(SystemFeatureConfigurationInformation, query);
}

std::optional<SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION> SystemInfo::GetFeatureConfigurationSectionInformation() {
	SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST request{};
	return QueryFixedEx<SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION>(SystemFeatureConfigurationSectionInformation, request);
}

std::vector<SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS> SystemInfo::GetFeatureUsageSubscriptionInformation() {
	return QueryArray<SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS>(SystemFeatureUsageSubscriptionInformation);
}

std::optional<SECURE_SPECULATION_CONTROL_INFORMATION> SystemInfo::GetSecureSpeculationControlInformation() {
	return QueryFixed<SECURE_SPECULATION_CONTROL_INFORMATION>(SystemSecureSpeculationControlInformation);
}

std::optional<SYSTEM_FIRMWARE_RAMDISK_INFORMATION> SystemInfo::GetFwRamdiskInformation() {
	return QueryFixed<SYSTEM_FIRMWARE_RAMDISK_INFORMATION>(SystemFwRamdiskInformation);
}

std::optional<SYSTEM_SHADOW_STACK_INFORMATION> SystemInfo::GetShadowStackInformation() {
	return QueryFixed<SYSTEM_SHADOW_STACK_INFORMATION>(SystemShadowStackInformation);
}

std::optional<SystemInfo::BuildVersion> SystemInfo::GetBuildVersionInformation(ULONG layer) {
	auto info = QueryFixedEx<SYSTEM_BUILD_VERSION_INFORMATION>(SystemBuildVersionInformation, layer);
	if (!info)
		return {};
	return BuildVersion{ *info, ToString(info->LayerName), ToString(info->NtBuildBranch), ToString(info->NtBuildLab),
		ToString(info->NtBuildLabEx), ToString(info->NtBuildStamp), ToString(info->NtBuildArch) };
}

std::vector<SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION> SystemInfo::GetSupportedProcessorArchitectures2(HANDLE hProcess) {
	return QueryArchitectures(SystemSupportedProcessorArchitectures2, hProcess);
}

std::vector<SystemInfo::LogicalProcessorRelationship> SystemInfo::GetSingleProcessorRelationshipInformation(PROCESSOR_NUMBER const& processor) {
	return ParseRelationships(Query(SystemSingleProcessorRelationshipInformation, 1 << 12, &processor, sizeof(processor)));
}

std::optional<SYSTEM_XFG_FAILURE_INFORMATION> SystemInfo::GetXfgCheckFailureInformation() {
	return QueryFixed<SYSTEM_XFG_FAILURE_INFORMATION>(SystemXfgCheckFailureInformation);
}

std::optional<SYSTEM_IOMMU_STATE_INFORMATION> SystemInfo::GetIommuStateInformation() {
	return QueryFixed<SYSTEM_IOMMU_STATE_INFORMATION>(SystemIommuStateInformation);
}

std::optional<SYSTEM_HYPERVISOR_MINROOT_INFORMATION> SystemInfo::GetHypervisorMinrootInformation() {
	return QueryFixed<SYSTEM_HYPERVISOR_MINROOT_INFORMATION>(SystemHypervisorMinrootInformation);
}

std::vector<ULONG_PTR> SystemInfo::GetHypervisorBootPagesInformation() {
	auto buffer = Query(SystemHypervisorBootPagesInformation, 1 << 10);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION, RangeArray))
		return {};
	auto info = reinterpret_cast<const SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION*>(buffer->data());
	return ToVector<ULONG_PTR>(*buffer, info->RangeArray, info->RangeCount);
}

std::optional<SYSTEM_POINTER_AUTH_INFORMATION> SystemInfo::GetPointerAuthInformation() {
	return QueryFixed<SYSTEM_POINTER_AUTH_INFORMATION>(SystemPointerAuthInformation);
}

std::optional<SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT> SystemInfo::GetOriginalImageFeatureInformation(PCWSTR featureName, ULONG bornOnVersion) {
	SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT input{ 1, const_cast<PWSTR>(featureName), bornOnVersion };
	return QueryFixedEx<SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT>(SystemOriginalImageFeatureInformation, input);
}

std::optional<SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT> SystemInfo::GetMemoryNumaInformation(ULONG targetNode) {
	SYSTEM_MEMORY_NUMA_INFORMATION_INPUT input{ 1, targetNode };
	return QueryFixedEx<SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT>(SystemMemoryNumaInformation, input);
}

std::vector<SYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY> SystemInfo::GetMemoryNumaPerformanceInformation(ULONG targetNode, SYSTEM_MEMORY_NUMA_PERFORMANCE_QUERY_DATA_TYPES dataType) {
	SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT input{ 1, targetNode, dataType };
	auto buffer = Query(SystemMemoryNumaPerformanceInformation, 1 << 12, &input, sizeof(input));
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT, PerformanceEntries))
		return {};
	auto info = reinterpret_cast<const SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT*>(buffer->data());
	return ToVector<SYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY>(*buffer, info->PerformanceEntries, info->EntryCount);
}

std::optional<SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION> SystemInfo::GetTrustedAppsRuntimeInformation() {
	return QueryFixed<SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION>(SystemTrustedAppsRuntimeInformation);
}

std::vector<SYSTEM_BAD_PAGE_INFORMATION> SystemInfo::GetBadPageInformationEx() {
	return QueryArray<SYSTEM_BAD_PAGE_INFORMATION>(SystemBadPageInformationEx);
}

std::optional<ULONG> SystemInfo::GetResourceDeadlockTimeout() {
	return QueryFixed<ULONG>(SystemResourceDeadlockTimeout);
}

std::optional<ULONG> SystemInfo::GetBreakOnContextUnwindFailureInformation() {
	return QueryFixed<ULONG>(SystemBreakOnContextUnwindFailureInformation);
}

std::vector<SYSTEM_OSL_RAMDISK_ENTRY> SystemInfo::GetOslRamdiskInformation() {
	auto buffer = Query(SystemOslRamdiskInformation, 1 << 10);
	if (!buffer || buffer->size() < FIELD_OFFSET(SYSTEM_OSL_RAMDISK_INFORMATION, Entries))
		return {};
	auto info = reinterpret_cast<const SYSTEM_OSL_RAMDISK_INFORMATION*>(buffer->data());
	return ToVector<SYSTEM_OSL_RAMDISK_ENTRY>(*buffer, info->Entries, info->Count);
}
