#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// Events from the Windows event logs (wevtapi): Query reads a channel's recent events, newest first (EvtQuery in reverse
// with an XPath of the levels and the time span), and EventLogWatcher gets the new ones as they're written
// (EvtSubscribe to future events, a callback on wevtapi's thread). Each event's system values come from EvtRender
// (EvtRenderContextSystem) and its message from EvtFormatMessage with its publisher's metadata (opened once per
// provider and kept). System and Application are readable without elevation; Security needs it, and its events are
// told by their audit keywords rather than their level (0).
//

namespace WinSys {
	// an event's data field ("TargetUserName", "zodia")
	struct EventDataItem {
		std::wstring Name, Value;
	};

	// which events' data fields a query reads (their XML rendered and parsed, ParseData: tens of microseconds an event,
	// against milliseconds to find one again by record ID, GetData, in a large log)
	enum class EventDataRead {
		None,
		All,
		NoMessage,	// those whose publisher has no message for them (the data is all there is)
	};

	struct EventLogEntry {
		uint64_t RecordId{ 0 };
		int64_t Time{ 0 };			// FILETIME (UTC)
		std::wstring Channel;		// "System"
		std::wstring Provider;		// "Service Control Manager"
		uint32_t EventId{ 0 };
		uint8_t Level{ 0 };			// 1 critical, 2 error, 3 warning, 4 information, 5 verbose (0: always logged)
		uint32_t ProcessId{ 0 }, ThreadId{ 0 };	// the logging process's (often the service host or the kernel's 4)
		uint64_t Keywords{ 0 };
		std::wstring Computer;
		std::wstring Message;		// the formatted message; empty if the publisher's resources have none
		std::vector<EventDataItem> Data;	// the data fields, when asked for (EventDataRead, EventLogWatcher::Start's data)

		// the Security log's events are level 0, told apart by these keywords
		static constexpr uint64_t AuditFailureKeyword = 0x10000000000000, AuditSuccessKeyword = 0x20000000000000;
		[[nodiscard]] bool IsAuditFailure() const;
		[[nodiscard]] bool IsAuditSuccess() const;
	};

	// gets the new events (on wevtapi's thread); a non-owning interface, as WinSys takes no std::function
	struct EventLogSink {
		virtual void OnEvent(EventLogEntry&& entry) = 0;
	};

	struct EventLog final {
		// a channel's events of the levels up to maxLevel (1-5; level 0 events count as information, audit failures as
		// warnings, so the Security log's failures come with the warnings and its successes with the information) from
		// the last hours, in reverse log order (by record ID: newest first unless the clock was set back, as a new VM does
		// when it syncs), at most maxEvents; nothing, with the last error set, if the channel can't be read (Security
		// without elevation: ERROR_ACCESS_DENIED... or ERROR_PRIVILEGE_NOT_HELD)
		[[nodiscard]] static std::optional<std::vector<EventLogEntry>> Query(std::wstring const& channel, uint8_t maxLevel,
			uint32_t hours, size_t maxEvents, EventDataRead data = EventDataRead::None);
		[[nodiscard]] static PCWSTR LevelName(uint8_t level);
		// the level's name, or Audit Failure / Audit Success for the Security log's events
		[[nodiscard]] static PCWSTR LevelText(EventLogEntry const& entry);
		// the channel is registered (EvtOpenLog; one the caller may not read, Security without elevation, counts)
		[[nodiscard]] static bool Exists(std::wstring const& channel);
		// an event's XML (EvtRender with EvtRenderEventXml: the system values and the event's data, which the message is
		// made from), found by its record ID; on one line, as rendered. Nothing (the last error set) if it's gone
		[[nodiscard]] static std::optional<std::wstring> GetXml(std::wstring const& channel, uint64_t recordId);
		// the event's data fields from its XML: <EventData>'s <Data Name='x'>value</Data> items (a name empty for the
		// unnamed ones), else the elements under <UserData>'s first child; the entities decoded (&amp; &lt; &#10;...)
		[[nodiscard]] static std::vector<EventDataItem> ParseData(std::wstring const& xml);
		// GetXml, then ParseData
		[[nodiscard]] static std::optional<std::vector<EventDataItem>> GetData(std::wstring const& channel, uint64_t recordId);
	};

	class EventLogWatcher {
	public:
		~EventLogWatcher();
		// a subscription per channel to the events of the levels up to maxLevel written from now on; false (the last error
		// set) if none could be made. The sink must outlive the watcher (Stop waits for a callback in progress). data: each
		// event's data fields read too (EventLogEntry::Data)
		bool Start(std::vector<std::wstring> const& channels, uint8_t maxLevel, EventLogSink& sink, bool data = false);
		// the same with a query of the caller's per channel: (channel, XPath such as "*[System[EventID=7031]]")
		bool Start(std::vector<std::pair<std::wstring, std::wstring>> const& queries, EventLogSink& sink, bool data = false);
		void Stop();
		[[nodiscard]] bool IsRunning() const;

		struct State;	// internal (public for the callback, which is the .cpp's)

	private:
		std::vector<void*> m_Subscriptions;	// EVT_HANDLE
		State* m_State{ nullptr };	// the sink, the render context and the publishers' metadata the callbacks share
	};
}
