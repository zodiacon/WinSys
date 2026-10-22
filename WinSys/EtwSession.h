#pragma once

// Internal to WinSys: what the real-time ETW trackers (ProcessNetworkTracker, IpcTracker) share. Include after
// <evntrace.h>.

#include <string>
#include <vector>
#include <wil/resource.h>

namespace WinSys::Etw {
	struct SessionProperties {
		EVENT_TRACE_PROPERTIES Properties;
		WCHAR Name[1024];
	};

	// mode: added to EVENT_TRACE_REAL_TIME_MODE (EVENT_TRACE_SYSTEM_LOGGER_MODE for the system providers)
	inline SessionProperties MakeProperties(ULONG mode = 0) {
		SessionProperties props{};
		props.Properties.Wnode.BufferSize = sizeof(props);
		props.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		props.Properties.Wnode.ClientContext = 1;	// QueryPerformanceCounter time stamps
		props.Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | mode;
		props.Properties.FlushTimer = 1;	// seconds
		props.Properties.LoggerNameOffset = offsetof(SessionProperties, Name);
		return props;
	}

	// stops "<prefix><pid>" sessions whose process is gone
	inline void StopOrphanedSessions(std::wstring const& prefix) {
		std::vector<SessionProperties> sessions(64);	// the most sessions the system allows
		std::vector<EVENT_TRACE_PROPERTIES*> pointers;
		for (auto& s : sessions) {
			s = MakeProperties();
			pointers.push_back(&s.Properties);
		}
		ULONG count = 0;
		if (::QueryAllTraces(pointers.data(), (ULONG)pointers.size(), &count) != ERROR_SUCCESS)
			return;
		for (ULONG i = 0; i < count; i++) {
			std::wstring_view name(sessions[i].Name);
			if (!name.starts_with(prefix))
				continue;
			auto pid = (DWORD)::_wtoi(name.data() + prefix.size());
			wil::unique_handle hProcess(::OpenProcess(SYNCHRONIZE, FALSE, pid));
			if (pid == 0 || (!hProcess && ::GetLastError() == ERROR_INVALID_PARAMETER)
				|| (hProcess && ::WaitForSingleObject(hProcess.get(), 0) == WAIT_OBJECT_0)) {
				auto stop = MakeProperties();
				::ControlTrace(0, sessions[i].Name, &stop.Properties, EVENT_TRACE_CONTROL_STOP);
			}
		}
	}

	// starts the session "<prefix><this process's ID>", after stopping orphaned ones and this process's own left over;
	// a Win32 error
	inline DWORD StartSession(std::wstring const& prefix, std::wstring& name, TRACEHANDLE& session, ULONG mode = 0) {
		StopOrphanedSessions(prefix);
		name = prefix + std::to_wstring(::GetCurrentProcessId());
		auto props = MakeProperties(mode);
		auto error = ::StartTrace(&session, name.c_str(), &props.Properties);
		if (error == ERROR_ALREADY_EXISTS) {
			// this process's, from a tracker that wasn't stopped
			auto stop = MakeProperties();
			::ControlTrace(0, name.c_str(), &stop.Properties, EVENT_TRACE_CONTROL_STOP);
			props = MakeProperties(mode);
			error = ::StartTrace(&session, name.c_str(), &props.Properties);
		}
		return error;
	}
}
