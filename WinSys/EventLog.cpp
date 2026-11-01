#include "pch.h"
#include "EventLog.h"
#include <winevt.h>
#include <wil/resource.h>
#include <unordered_map>

#pragma comment(lib, "wevtapi")

using namespace WinSys;

namespace {
	// the publishers' metadata (for their messages), opened once each; shared by callbacks that may run at once
	class PublisherCache {
	public:
		~PublisherCache() {
			for (auto& [name, h] : m_Handles)
				if (h)
					::EvtClose(h);
		}

		EVT_HANDLE Get(std::wstring const& provider) {
			auto lock = m_Lock.lock_exclusive();
			if (auto it = m_Handles.find(provider); it != m_Handles.end())
				return it->second;
			auto h = ::EvtOpenPublisherMetadata(nullptr, provider.c_str(), nullptr, 0, 0);
			m_Handles[provider] = h;	// null too: not tried again
			return h;
		}

	private:
		wil::srwlock m_Lock;
		std::unordered_map<std::wstring, EVT_HANDLE> m_Handles;
	};

	std::wstring FormatMessageOf(EVT_HANDLE hMetadata, EVT_HANDLE hEvent) {
		std::vector<WCHAR> buffer(1024);
		for (int tries = 0; tries < 2; tries++) {
			DWORD used = 0;
			if (::EvtFormatMessage(hMetadata, hEvent, 0, 0, nullptr, EvtFormatMessageEvent, (DWORD)buffer.size(), buffer.data(), &used)) {
				std::wstring text(buffer.data());
				// the messages end with line breaks
				while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' '))
					text.pop_back();
				return text;
			}
			if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				break;
			buffer.resize(used + 1);
		}
		return L"";
	}

	bool Render(EVT_HANDLE hContext, EVT_HANDLE hEvent, PublisherCache& publishers, EventLogEntry& entry) {
		std::vector<BYTE> buffer(1024);
		DWORD used = 0, count = 0;
		if (!::EvtRender(hContext, hEvent, EvtRenderEventValues, (DWORD)buffer.size(), buffer.data(), &used, &count)) {
			if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				return false;
			buffer.resize(used);
			if (!::EvtRender(hContext, hEvent, EvtRenderEventValues, (DWORD)buffer.size(), buffer.data(), &used, &count))
				return false;
		}
		auto values = reinterpret_cast<PEVT_VARIANT>(buffer.data());
		auto string = [&](int index) {
			return index < (int)count && values[index].Type == EvtVarTypeString && values[index].StringVal ? std::wstring(values[index].StringVal) : std::wstring();
		};
		entry.Provider = string(EvtSystemProviderName);
		entry.Channel = string(EvtSystemChannel);
		entry.Computer = string(EvtSystemComputer);
		if (values[EvtSystemEventID].Type == EvtVarTypeUInt16)
			entry.EventId = values[EvtSystemEventID].UInt16Val;
		if (values[EvtSystemLevel].Type == EvtVarTypeByte)
			entry.Level = values[EvtSystemLevel].ByteVal;
		if (values[EvtSystemTimeCreated].Type == EvtVarTypeFileTime)
			entry.Time = (int64_t)values[EvtSystemTimeCreated].FileTimeVal;
		if (values[EvtSystemEventRecordId].Type == EvtVarTypeUInt64)
			entry.RecordId = values[EvtSystemEventRecordId].UInt64Val;
		if (values[EvtSystemProcessID].Type == EvtVarTypeUInt32)
			entry.ProcessId = values[EvtSystemProcessID].UInt32Val;
		if (values[EvtSystemThreadID].Type == EvtVarTypeUInt32)
			entry.ThreadId = values[EvtSystemThreadID].UInt32Val;
		if (values[EvtSystemKeywords].Type == EvtVarTypeHexInt64 || values[EvtSystemKeywords].Type == EvtVarTypeUInt64)
			entry.Keywords = values[EvtSystemKeywords].UInt64Val;
		entry.Message = FormatMessageOf(entry.Provider.empty() ? nullptr : publishers.Get(entry.Provider), hEvent);
		return true;
	}

	// the levels up to maxLevel; level 0 (logged always, as nearly all of Security's) with the information events, and the
	// audit failures (Security's level 0 events with that keyword) with the warnings. Only Security's events have the
	// audit keywords, so the same query does for every log
	std::wstring LevelsXPath(uint8_t maxLevel) {
		std::wstring levels;
		for (int level = 1; level <= maxLevel && level <= 5; level++)
			levels += (levels.empty() ? L"" : L" or ") + std::wstring(L"Level=") + std::to_wstring(level);
		if (maxLevel >= 4)
			levels += L" or Level=0";
		else if (maxLevel >= 3)
			levels += L" or band(Keywords," + std::to_wstring(EventLogEntry::AuditFailureKeyword) + L")";
		return L"(" + levels + L")";
	}
}

bool EventLogEntry::IsAuditFailure() const {
	return (Keywords & AuditFailureKeyword) != 0;
}

bool EventLogEntry::IsAuditSuccess() const {
	return (Keywords & AuditSuccessKeyword) != 0;
}

PCWSTR EventLog::LevelText(EventLogEntry const& entry) {
	if (entry.IsAuditFailure())
		return L"Audit Failure";
	if (entry.IsAuditSuccess())
		return L"Audit Success";
	return LevelName(entry.Level);
}

PCWSTR EventLog::LevelName(uint8_t level) {
	switch (level) {
		case 1: return L"Critical";
		case 2: return L"Error";
		case 3: return L"Warning";
		case 0: case 4: return L"Information";
		case 5: return L"Verbose";
	}
	return L"";
}

std::optional<std::vector<EventLogEntry>> EventLog::Query(std::wstring const& channel, uint8_t maxLevel, uint32_t hours, size_t maxEvents) {
	auto query = L"*[System[" + LevelsXPath(maxLevel) + L" and TimeCreated[timediff(@SystemTime) <= "
		+ std::to_wstring((uint64_t)hours * 3600000) + L"]]]";
	auto hQuery = ::EvtQuery(nullptr, channel.c_str(), query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
	if (!hQuery)
		return std::nullopt;
	auto hContext = ::EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
	PublisherCache publishers;
	std::vector<EventLogEntry> entries;
	EVT_HANDLE events[64];
	DWORD returned = 0;
	while (entries.size() < maxEvents && ::EvtNext(hQuery, _countof(events), events, INFINITE, 0, &returned)) {
		for (DWORD i = 0; i < returned; i++) {
			EventLogEntry entry;
			if (entries.size() < maxEvents && Render(hContext, events[i], publishers, entry))
				entries.push_back(std::move(entry));
			::EvtClose(events[i]);
		}
	}
	if (hContext)
		::EvtClose(hContext);
	::EvtClose(hQuery);
	return entries;
}

struct EventLogWatcher::State {
	EventLogSink* Sink{ nullptr };
	EVT_HANDLE Context{ nullptr };
	PublisherCache Publishers;

	~State() {
		if (Context)
			::EvtClose(Context);
	}
};

namespace {
	DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE hEvent);
}

EventLogWatcher::~EventLogWatcher() {
	Stop();
}

bool EventLogWatcher::IsRunning() const {
	return !m_Subscriptions.empty();
}

bool EventLogWatcher::Start(std::vector<std::wstring> const& channels, uint8_t maxLevel, EventLogSink& sink) {
	Stop();
	m_State = new State;
	m_State->Sink = &sink;
	m_State->Context = ::EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
	auto query = L"*[System[" + LevelsXPath(maxLevel) + L"]]";
	DWORD error = 0;
	for (auto& channel : channels) {
		auto h = ::EvtSubscribe(nullptr, nullptr, channel.c_str(), query.c_str(), nullptr, m_State,
			(EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeToFutureEvents);
		if (h)
			m_Subscriptions.push_back(h);
		else
			error = ::GetLastError();
	}
	if (m_Subscriptions.empty()) {
		Stop();
		::SetLastError(error);
		return false;
	}
	return true;
}

void EventLogWatcher::Stop() {
	// closing a subscription waits for its callback in progress
	for (auto h : m_Subscriptions)
		::EvtClose(h);
	m_Subscriptions.clear();
	delete m_State;
	m_State = nullptr;
}

namespace {
	DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE hEvent) {
		if (action != EvtSubscribeActionDeliver)
			return ERROR_SUCCESS;
		auto state = static_cast<EventLogWatcher::State*>(context);
		EventLogEntry entry;
		if (Render(state->Context, hEvent, state->Publishers, entry))
			state->Sink->OnEvent(std::move(entry));
		return ERROR_SUCCESS;
	}
}
