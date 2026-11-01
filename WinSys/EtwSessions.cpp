#include "pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include "EtwSessions.h"
#include <map>
#include <memory>

#pragma comment(lib, "tdh")

using namespace WinSys;

namespace {
	struct GuidLess {
		bool operator()(GUID const& a, GUID const& b) const {
			return memcmp(&a, &b, sizeof(GUID)) < 0;
		}
	};

	// the providers TDH knows, by GUID
	std::map<GUID, std::wstring, GuidLess> ProviderNames() {
		std::map<GUID, std::wstring, GuidLess> names;
		ULONG size = 0;
		if (::TdhEnumerateProviders(nullptr, &size) != ERROR_INSUFFICIENT_BUFFER)
			return names;
		// the list may grow between the calls
		for (int attempt = 0; attempt < 3; attempt++) {
			auto buffer = std::make_unique<BYTE[]>(size);
			auto info = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buffer.get());
			auto error = ::TdhEnumerateProviders(info, &size);
			if (error == ERROR_INSUFFICIENT_BUFFER)
				continue;
			if (error != ERROR_SUCCESS)
				break;
			for (ULONG i = 0; i < info->NumberOfProviders; i++) {
				auto& p = info->TraceProviderInfoArray[i];
				names.emplace(p.ProviderGuid, reinterpret_cast<PCWSTR>(buffer.get() + p.ProviderNameOffset));
			}
			break;
		}
		return names;
	}

	std::wstring ModeText(ULONG mode) {
		std::wstring text;
		auto add = [&](PCWSTR part) {
			if (!text.empty())
				text += L", ";
			text += part;
		};
		if (mode & EVENT_TRACE_REAL_TIME_MODE)
			add(L"Real time");
		if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR)
			add(L"File (circular)");
		else if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL)
			add(L"File (sequential)");
		if (mode & EVENT_TRACE_FILE_MODE_NEWFILE)
			add(L"New file");
		if (mode & EVENT_TRACE_FILE_MODE_APPEND)
			add(L"Append");
		if (mode & EVENT_TRACE_BUFFERING_MODE)
			add(L"Buffering");
		if (mode & EVENT_TRACE_PRIVATE_LOGGER_MODE)
			add(L"Private");
		if (mode & EVENT_TRACE_SYSTEM_LOGGER_MODE)
			add(L"System logger");
		if (mode & EVENT_TRACE_INDEPENDENT_SESSION_MODE)
			add(L"Independent");
		return text;
	}

	// a provider's instances and the sessions that enabled each (TraceGuidQueryInfo), into the sessions by logger ID
	void AddProvider(GUID const& guid, std::vector<EtwSession>& sessions, std::map<GUID, std::wstring, GuidLess> const& names) {
		ULONG size = 1024;
		std::unique_ptr<BYTE[]> buffer;
		ULONG error = ERROR_INSUFFICIENT_BUFFER;
		for (int attempt = 0; attempt < 4 && error == ERROR_INSUFFICIENT_BUFFER; attempt++) {
			buffer = std::make_unique<BYTE[]>(size);
			ULONG needed = 0;
			error = ::EnumerateTraceGuidsEx(TraceGuidQueryInfo, const_cast<GUID*>(&guid), sizeof(GUID), buffer.get(), size, &needed);
			if (error == ERROR_INSUFFICIENT_BUFFER)
				size = needed > size ? needed : size * 2;
		}
		if (error != ERROR_SUCCESS)
			return;
		auto info = reinterpret_cast<TRACE_GUID_INFO const*>(buffer.get());
		auto instance = reinterpret_cast<TRACE_PROVIDER_INSTANCE_INFO const*>(info + 1);
		for (ULONG i = 0; i < info->InstanceCount; i++) {
			auto enables = reinterpret_cast<TRACE_ENABLE_INFO const*>(instance + 1);
			for (ULONG e = 0; e < instance->EnableCount; e++) {
				auto& enable = enables[e];
				if (!enable.IsEnabled)
					continue;
				for (auto& s : sessions) {
					if (s.LoggerId != enable.LoggerId)
						continue;
					auto it = std::find_if(s.Providers.begin(), s.Providers.end(), [&](auto& p) { return p.Id == guid; });
					if (it == s.Providers.end()) {
						EtwSessionProvider p;
						p.Id = guid;
						if (auto name = names.find(guid); name != names.end())
							p.Name = name->second;
						p.Level = enable.Level;
						p.MatchAnyKeyword = enable.MatchAnyKeyword;
						p.MatchAllKeyword = enable.MatchAllKeyword;
						s.Providers.push_back(std::move(p));
						it = s.Providers.end() - 1;
					}
					if (std::find(it->Pids.begin(), it->Pids.end(), instance->Pid) == it->Pids.end())
						it->Pids.push_back(instance->Pid);
					break;
				}
			}
			if (instance->NextOffset == 0)
				break;
			instance = reinterpret_cast<TRACE_PROVIDER_INSTANCE_INFO const*>(reinterpret_cast<BYTE const*>(instance) + instance->NextOffset);
		}
	}
}

std::optional<std::vector<EtwSession>> EtwSessions::Enum() {
	// room for each session's name and log file after its properties
	struct Properties {
		EVENT_TRACE_PROPERTIES Props;
		WCHAR LoggerName[1024];
		WCHAR LogFileName[1024];
	};
	ULONG capacity = 64;
	std::vector<Properties> storage;
	std::vector<EVENT_TRACE_PROPERTIES*> pointers;
	ULONG count = 0;
	ULONG error = ERROR_MORE_DATA;
	for (int attempt = 0; attempt < 3 && error == ERROR_MORE_DATA; attempt++) {
		storage.assign(capacity, Properties{});
		pointers.clear();
		for (auto& p : storage) {
			p.Props.Wnode.BufferSize = sizeof(Properties);
			p.Props.LoggerNameOffset = offsetof(Properties, LoggerName);
			p.Props.LogFileNameOffset = offsetof(Properties, LogFileName);
			pointers.push_back(&p.Props);
		}
		error = ::QueryAllTracesW(pointers.data(), capacity, &count);
		if (error == ERROR_MORE_DATA)
			capacity = count > capacity ? count : capacity * 2;
	}
	if (error != ERROR_SUCCESS) {
		::SetLastError(error);
		return std::nullopt;
	}

	std::vector<EtwSession> sessions;
	sessions.reserve(count);
	for (ULONG i = 0; i < count; i++) {
		auto& p = storage[i];
		auto& props = p.Props;
		EtwSession s;
		// the session's logger ID is in the low word of the handle QueryAllTraces puts in the WNODE
		s.LoggerId = (uint32_t)(props.Wnode.HistoricalContext & 0xFFFF);
		s.Name = p.LoggerName;
		s.LogFile = p.LogFileName;
		s.LogFileMode = props.LogFileMode;
		s.Mode = ModeText(props.LogFileMode);
		s.BufferSizeKB = props.BufferSize;
		s.Buffers = props.NumberOfBuffers;
		s.FreeBuffers = props.FreeBuffers;
		s.MinimumBuffers = props.MinimumBuffers;
		s.MaximumBuffers = props.MaximumBuffers;
		s.EventsLost = props.EventsLost;
		s.BuffersWritten = props.BuffersWritten;
		s.LogBuffersLost = props.LogBuffersLost;
		s.RealTimeBuffersLost = props.RealTimeBuffersLost;
		s.FlushTimer = props.FlushTimer;
		s.EnableFlags = props.EnableFlags;
		sessions.push_back(std::move(s));
	}

	// every registered provider, then which sessions enabled it
	ULONG size = 0;
	if (::EnumerateTraceGuidsEx(TraceGuidQueryList, nullptr, 0, nullptr, 0, &size) == ERROR_INSUFFICIENT_BUFFER && size) {
		std::vector<GUID> guids(size / sizeof(GUID) + 16);
		ULONG needed = 0;
		if (::EnumerateTraceGuidsEx(TraceGuidQueryList, nullptr, 0, guids.data(), (ULONG)(guids.size() * sizeof(GUID)), &needed) == ERROR_SUCCESS) {
			guids.resize(needed / sizeof(GUID));
			auto names = ProviderNames();
			for (auto& guid : guids)
				AddProvider(guid, sessions, names);
		}
	}
	return sessions;
}

std::wstring EtwSessions::LevelName(uint8_t level) {
	switch (level) {
		case TRACE_LEVEL_NONE: return L"Always";
		case TRACE_LEVEL_CRITICAL: return L"Critical";
		case TRACE_LEVEL_ERROR: return L"Error";
		case TRACE_LEVEL_WARNING: return L"Warning";
		case TRACE_LEVEL_INFORMATION: return L"Information";
		case TRACE_LEVEL_VERBOSE: return L"Verbose";
		case 0xFF: return L"All";
	}
	return std::to_wstring(level);
}

bool EtwSessions::Stop(std::wstring const& name) {
	// the properties with room for the names ControlTrace writes back
	struct {
		EVENT_TRACE_PROPERTIES Properties;
		WCHAR Names[2048];
	} props{};
	props.Properties.Wnode.BufferSize = sizeof(props);
	props.Properties.LoggerNameOffset = offsetof(decltype(props), Names);
	props.Properties.LogFileNameOffset = offsetof(decltype(props), Names) + 1024 * sizeof(WCHAR);
	auto error = ::ControlTraceW(0, name.c_str(), &props.Properties, EVENT_TRACE_CONTROL_STOP);
	// ERROR_MORE_DATA: stopped, but the statistics didn't fit
	if (error != ERROR_SUCCESS && error != ERROR_MORE_DATA) {
		::SetLastError(error);
		return false;
	}
	return true;
}
