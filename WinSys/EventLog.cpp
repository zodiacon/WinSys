#include "pch.h"
#include "EventLog.h"
#include <winevt.h>
#include <wil/resource.h>
#include <unordered_map>
#include <string_view>

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

namespace {
	// an event's XML (EvtRenderEventXml)
	std::optional<std::wstring> RenderXml(EVT_HANDLE hEvent) {
		DWORD used = 0, count = 0;
		std::vector<WCHAR> buffer(4096);
		if (!::EvtRender(nullptr, hEvent, EvtRenderEventXml, (DWORD)(buffer.size() * sizeof(WCHAR)), buffer.data(), &used, &count)) {
			if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				return std::nullopt;
			buffer.resize(used / sizeof(WCHAR) + 1);
			if (!::EvtRender(nullptr, hEvent, EvtRenderEventXml, (DWORD)(buffer.size() * sizeof(WCHAR)), buffer.data(), &used, &count))
				return std::nullopt;
		}
		return std::wstring(buffer.data());
	}

	// the rendered event's data fields, if the mode wants them
	void ReadData(EVT_HANDLE hEvent, EventDataRead mode, EventLogEntry& entry) {
		if (mode == EventDataRead::None || (mode == EventDataRead::NoMessage && !entry.Message.empty()))
			return;
		if (auto xml = RenderXml(hEvent))
			entry.Data = EventLog::ParseData(*xml);
	}
}

std::optional<std::wstring> EventLog::GetXml(std::wstring const& channel, uint64_t recordId) {
	auto query = L"*[System[EventRecordID=" + std::to_wstring(recordId) + L"]]";
	wil::unique_any<EVT_HANDLE, decltype(&::EvtClose), ::EvtClose> hQuery(::EvtQuery(nullptr, channel.c_str(), query.c_str(), EvtQueryChannelPath));
	if (!hQuery)
		return std::nullopt;
	EVT_HANDLE hEvent = nullptr;
	DWORD returned = 0;
	if (!::EvtNext(hQuery.get(), 1, &hEvent, INFINITE, 0, &returned) || returned == 0) {
		if (::GetLastError() == ERROR_NO_MORE_ITEMS)
			::SetLastError(ERROR_NOT_FOUND);
		return std::nullopt;
	}
	wil::unique_any<EVT_HANDLE, decltype(&::EvtClose), ::EvtClose> event(hEvent);
	return RenderXml(event.get());
}

bool EventLog::Exists(std::wstring const& channel) {
	if (auto h = ::EvtOpenLog(nullptr, channel.c_str(), EvtOpenChannelPath)) {
		::EvtClose(h);
		return true;
	}
	return ::GetLastError() != ERROR_EVT_CHANNEL_NOT_FOUND;
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

std::optional<std::vector<EventLogEntry>> EventLog::Query(std::wstring const& channel, uint8_t maxLevel, uint32_t hours, size_t maxEvents,
	EventDataRead data, std::wstring const& provider) {
	// a provider's name has no quotes in it
	auto providerPath = provider.empty() || provider.find_first_of(L"'\"") != std::wstring::npos ? std::wstring()
		: L"Provider[@Name='" + provider + L"'] and ";
	auto query = L"*[System[" + providerPath + LevelsXPath(maxLevel) + L" and TimeCreated[timediff(@SystemTime) <= "
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
			if (entries.size() < maxEvents && Render(hContext, events[i], publishers, entry)) {
				ReadData(events[i], data, entry);
				entries.push_back(std::move(entry));
			}
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
	bool Data{ false };	// the events' data fields read too
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

bool EventLogWatcher::Start(std::vector<std::wstring> const& channels, uint8_t maxLevel, EventLogSink& sink, bool data) {
	auto query = L"*[System[" + LevelsXPath(maxLevel) + L"]]";
	std::vector<std::pair<std::wstring, std::wstring>> queries;
	for (auto& channel : channels)
		queries.push_back({ channel, query });
	return Start(queries, sink, data);
}

bool EventLogWatcher::Start(std::vector<std::pair<std::wstring, std::wstring>> const& queries, EventLogSink& sink, bool data) {
	Stop();
	m_State = new State;
	m_State->Sink = &sink;
	m_State->Data = data;
	m_State->Context = ::EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
	DWORD error = ERROR_INVALID_PARAMETER;
	for (auto& [channel, query] : queries) {
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
		if (Render(state->Context, hEvent, state->Publishers, entry)) {
			ReadData(hEvent, state->Data ? EventDataRead::All : EventDataRead::None, entry);
			state->Sink->OnEvent(std::move(entry));
		}
		return ERROR_SUCCESS;
	}
}

namespace {
	// &amp; &lt; &gt; &quot; &apos; &#N; &#xN; decoded; tags inside a value (a nested element's) dropped
	std::wstring DecodeText(std::wstring_view text) {
		std::wstring result;
		result.reserve(text.size());
		for (size_t i = 0; i < text.size(); i++) {
			auto c = text[i];
			if (c == L'<') {
				auto end = text.find(L'>', i);
				if (end == std::wstring_view::npos)
					break;
				i = end;
				continue;
			}
			if (c != L'&') {
				result += c;
				continue;
			}
			auto semi = text.find(L';', i);
			if (semi == std::wstring_view::npos || semi - i > 10) {
				result += c;
				continue;
			}
			auto entity = text.substr(i + 1, semi - i - 1);
			if (entity == L"amp") result += L'&';
			else if (entity == L"lt") result += L'<';
			else if (entity == L"gt") result += L'>';
			else if (entity == L"quot") result += L'"';
			else if (entity == L"apos") result += L'\'';
			else if (entity.size() > 1 && entity[0] == L'#') {
				bool hex = entity[1] == L'x' || entity[1] == L'X';
				auto digits = std::wstring(entity.substr(hex ? 2 : 1));
				auto value = ::wcstoul(digits.c_str(), nullptr, hex ? 16 : 10);
				if (value > 0 && value <= 0xFFFF)
					result += (wchar_t)value;
				else if (value > 0xFFFF && value <= 0x10FFFF) {
					value -= 0x10000;
					result += (wchar_t)(0xD800 + (value >> 10));
					result += (wchar_t)(0xDC00 + (value & 0x3FF));
				}
			}
			else {
				result.append(text.substr(i, semi - i + 1));	// unknown: kept
			}
			i = semi;
		}
		return result;
	}

	// an attribute's value in a tag ("<Data Name='x'>"), either quote; empty if it has none
	std::wstring Attribute(std::wstring_view tag, std::wstring_view name) {
		for (size_t pos = tag.find(name); pos != std::wstring_view::npos; pos = tag.find(name, pos + 1)) {
			// a whole attribute name: after a space, followed by '=' (spaces allowed)
			if (pos == 0 || !iswspace(tag[pos - 1]))
				continue;
			auto i = pos + name.size();
			while (i < tag.size() && iswspace(tag[i]))
				i++;
			if (i >= tag.size() || tag[i] != L'=')
				continue;
			i++;
			while (i < tag.size() && iswspace(tag[i]))
				i++;
			if (i >= tag.size() || (tag[i] != L'\'' && tag[i] != L'"'))
				continue;
			auto end = tag.find(tag[i], i + 1);
			if (end == std::wstring_view::npos)
				return L"";
			return DecodeText(tag.substr(i + 1, end - i - 1));
		}
		return L"";
	}

	// the element's start tag at pos ("<Name ...>" or "<Name/>"): its name, where its content starts, and whether it's
	// empty; false if pos isn't at one
	struct Element {
		std::wstring_view Name, Tag;
		size_t ContentStart{ 0 };
		bool Empty{ false };
	};
	bool ReadElement(std::wstring_view xml, size_t pos, Element& element) {
		if (pos >= xml.size() || xml[pos] != L'<' || pos + 1 >= xml.size() || xml[pos + 1] == L'/' || xml[pos + 1] == L'?' || xml[pos + 1] == L'!')
			return false;
		auto end = xml.find(L'>', pos);
		if (end == std::wstring_view::npos)
			return false;
		element.Tag = xml.substr(pos, end - pos + 1);
		auto nameEnd = pos + 1;
		while (nameEnd < end && !iswspace(xml[nameEnd]) && xml[nameEnd] != L'/' && xml[nameEnd] != L'>')
			nameEnd++;
		element.Name = xml.substr(pos + 1, nameEnd - pos - 1);
		element.Empty = xml[end - 1] == L'/';
		element.ContentStart = end + 1;
		return true;
	}

	// where the element's content ends (its end tag), npos if it isn't there; nested elements of the same name counted
	size_t ContentEnd(std::wstring_view xml, Element const& element) {
		std::wstring open = L"<" + std::wstring(element.Name), close = L"</" + std::wstring(element.Name) + L">";
		int depth = 1;
		for (size_t pos = element.ContentStart; pos < xml.size(); ) {
			auto next = xml.find(L'<', pos);
			if (next == std::wstring_view::npos)
				return std::wstring_view::npos;
			if (xml.substr(next, close.size()) == close) {
				if (--depth == 0)
					return next;
				pos = next + close.size();
				continue;
			}
			Element inner;
			if (ReadElement(xml, next, inner) && inner.Name == element.Name && !inner.Empty)
				depth++;
			pos = next + 1;
		}
		return std::wstring_view::npos;
	}

	// the first element of the name in xml, from pos
	bool FindElement(std::wstring_view xml, std::wstring_view name, size_t from, Element& element) {
		std::wstring open = L"<" + std::wstring(name);
		for (auto pos = xml.find(open, from); pos != std::wstring_view::npos; pos = xml.find(open, pos + 1))
			if (ReadElement(xml, pos, element) && element.Name == name)
				return true;
		return false;
	}

	// the child elements in [start, end): each one's name and decoded content
	template<typename F>
	void ForEachChild(std::wstring_view xml, size_t start, size_t end, F&& f) {
		for (auto pos = xml.find(L'<', start); pos != std::wstring_view::npos && pos < end; ) {
			Element child;
			if (!ReadElement(xml, pos, child)) {
				pos = xml.find(L'<', pos + 1);
				continue;
			}
			if (child.Empty) {
				f(child, std::wstring());
				pos = xml.find(L'<', child.ContentStart);
				continue;
			}
			auto contentEnd = ContentEnd(xml, child);
			if (contentEnd == std::wstring_view::npos || contentEnd > end)
				break;
			f(child, DecodeText(xml.substr(child.ContentStart, contentEnd - child.ContentStart)));
			pos = xml.find(L'<', contentEnd + child.Name.size() + 3);
		}
	}
}

std::vector<EventDataItem> EventLog::ParseData(std::wstring const& text) {
	std::wstring_view xml(text);
	std::vector<EventDataItem> items;
	Element section;
	if (FindElement(xml, L"EventData", 0, section)) {
		if (section.Empty)
			return items;
		auto end = ContentEnd(xml, section);
		if (end == std::wstring_view::npos)
			return items;
		ForEachChild(xml, section.ContentStart, end, [&](Element const& child, std::wstring value) {
			if (child.Name == L"Data")
				items.push_back({ Attribute(child.Tag, L"Name"), std::move(value) });
			});
		return items;
	}
	// <UserData><SomeEvent xmlns='...'><Field>value</Field>...</SomeEvent></UserData>
	if (!FindElement(xml, L"UserData", 0, section) || section.Empty)
		return items;
	auto end = ContentEnd(xml, section);
	Element root;
	auto first = xml.find(L'<', section.ContentStart);
	if (end == std::wstring_view::npos || first == std::wstring_view::npos || first >= end || !ReadElement(xml, first, root) || root.Empty)
		return items;
	auto rootEnd = ContentEnd(xml, root);
	if (rootEnd == std::wstring_view::npos || rootEnd > end)
		return items;
	ForEachChild(xml, root.ContentStart, rootEnd, [&](Element const& child, std::wstring value) {
		items.push_back({ std::wstring(child.Name), std::move(value) });
		});
	return items;
}

std::optional<std::vector<EventDataItem>> EventLog::GetData(std::wstring const& channel, uint64_t recordId) {
	auto xml = GetXml(channel, recordId);
	if (!xml)
		return std::nullopt;
	return ParseData(*xml);
}
