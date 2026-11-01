#include "pch.h"
#include "PowerRequests.h"
#include "Handles.h"
#include <wil/resource.h>
#include <algorithm>

using namespace WinSys;

namespace {
	// phnt's layouts (POWER_REQUEST V4, DIAGNOSTIC_BUFFER, COUNTED_REASON_CONTEXT_RELATIVE, WAKE_TIMER_INFO), defined here
	// as the library's PHNT_VERSION (Threshold) leaves V4 out. The diagnostic buffer's strings are at offsets from its
	// start; a reason's strings at offsets from the reason's
	struct Diagnostic {
		SIZE_T Size;
		ULONG CallerType;	// 0 kernel (a driver), 1 process, 2 service
		union {
			struct {
				SIZE_T ProcessImageNameOffset;
				ULONG ProcessId;
				ULONG ServiceTag;
			} Process;
			struct {
				SIZE_T DeviceDescriptionOffset;
				SIZE_T DevicePathOffset;
			} Device;
		};
		SIZE_T ReasonOffset;
	};

	struct RequestV4 {
		ULONG SupportedRequestMask;
		ULONG Counts[6];
		Diagnostic Diag;
	};

	struct Reason {
		ULONG Flags;	// POWER_REQUEST_CONTEXT_SIMPLE_STRING, POWER_REQUEST_CONTEXT_DETAILED_STRING
		union {
			struct {
				SIZE_T ResourceFileNameOffset;
				USHORT ResourceReasonId;
				ULONG StringCount;
				SIZE_T SubstitutionStringsOffset;	// the strings, one after the other
			} Detailed;
			SIZE_T SimpleStringOffset;
		};
	};

	struct WakeTimerInfo {
		SIZE_T OffsetToNext;
		LARGE_INTEGER DueTime;	// the time left, 100 ns
		ULONG Period;			// ms
		Diagnostic Diag;
	};

	const int GetPowerRequestListLevel = 45, WakeTimerListLevel = 50;

	// the level's output, the buffer grown until it fits
	std::optional<std::vector<BYTE>> Query(int level) {
		std::vector<BYTE> buffer(8192);
		for (;;) {
			auto status = ::NtPowerInformation((POWER_INFORMATION_LEVEL)level, nullptr, 0, buffer.data(), (ULONG)buffer.size());
			if (status == STATUS_BUFFER_TOO_SMALL && buffer.size() < (1 << 24)) {
				buffer.resize(buffer.size() * 2);
				continue;
			}
			if (!NT_SUCCESS(status)) {
				::SetLastError(::RtlNtStatusToDosError(status));
				return std::nullopt;
			}
			return buffer;
		}
	}

	// a string at an offset from base, within [base, end); empty if it isn't there
	std::wstring StringAt(BYTE const* base, SIZE_T offset, BYTE const* end) {
		if (offset == 0 || base + offset >= end)
			return L"";
		auto start = reinterpret_cast<PCWSTR>(base + offset);
		auto max = (end - (base + offset)) / (ptrdiff_t)sizeof(WCHAR);
		return std::wstring(start, ::wcsnlen(start, max));
	}

	// a service's name from its tag (advapi32's I_QueryTagInformation, undocumented, which sc and powercfg use)
	std::wstring ServiceFromTag(uint32_t pid, uint32_t tag) {
		struct TagInfo {
			DWORD Pid, Tag;
			DWORD TagType;
			PWSTR Name;
		};
		using QueryTag = ULONG(WINAPI*)(PCWSTR, ULONG, PVOID);
		// loaded, as the caller may not have it yet (kept: a static's for the process)
		static auto query = (QueryTag)::GetProcAddress(::LoadLibraryExW(L"advapi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32),
			"I_QueryTagInformation");
		if (!query || !tag)
			return L"";
		TagInfo info{ pid, tag };
		if (query(nullptr, 1, &info) != ERROR_SUCCESS || !info.Name)	// 1: eTagInfoLevelNameFromTag
			return L"";
		std::wstring name = info.Name;
		::LocalFree(info.Name);
		return name;
	}

	// a resource string (the module as a data file, from System32 when the name has no path) with its %1... substitutions
	std::wstring ResourceString(std::wstring const& module, USHORT id, std::vector<std::wstring> const& args) {
		wil::unique_hmodule hModule(::LoadLibraryExW(module.c_str(), nullptr,
			LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_SEARCH_SYSTEM32));
		if (!hModule)
			return L"";
		PCWSTR text = nullptr;
		auto length = ::LoadStringW(hModule.get(), id, (PWSTR)&text, 0);
		if (length <= 0 || !text)
			return L"";
		std::wstring format(text, length);
		if (args.empty())
			return format;
		std::vector<DWORD_PTR> pointers;
		for (auto& a : args)
			pointers.push_back((DWORD_PTR)a.c_str());
		PWSTR result = nullptr;
		if (!::FormatMessageW(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_ALLOCATE_BUFFER,
			format.c_str(), 0, 0, (PWSTR)&result, 0, (va_list*)pointers.data()))
			return format;
		std::wstring formatted = result;
		::LocalFree(result);
		return formatted;
	}

	std::wstring ReasonText(BYTE const* diagBase, SIZE_T offset, BYTE const* end) {
		if (offset == 0 || diagBase + offset + sizeof(Reason) > end)
			return L"";
		auto reasonBase = diagBase + offset;
		auto& reason = *reinterpret_cast<Reason const*>(reasonBase);
		if (reason.Flags & POWER_REQUEST_CONTEXT_SIMPLE_STRING)
			return StringAt(reasonBase, reason.SimpleStringOffset, end);
		if (reason.Flags & POWER_REQUEST_CONTEXT_DETAILED_STRING) {
			auto module = StringAt(reasonBase, reason.Detailed.ResourceFileNameOffset, end);
			std::vector<std::wstring> args;
			auto offsetOfString = reason.Detailed.SubstitutionStringsOffset;
			for (ULONG i = 0; i < reason.Detailed.StringCount && i < 16 && offsetOfString; i++) {
				auto s = StringAt(reasonBase, offsetOfString, end);
				offsetOfString += (s.size() + 1) * sizeof(WCHAR);
				args.push_back(std::move(s));
			}
			auto text = ResourceString(module, reason.Detailed.ResourceReasonId, args);
			// the module and ID when the string can't be read
			return text.empty() && !module.empty() ? module + L" #" + std::to_wstring(reason.Detailed.ResourceReasonId) : text;
		}
		return L"";
	}

	void ReadSource(PowerRequestSource& source, Diagnostic const& diag, BYTE const* end, DosNames const& dosNames) {
		auto diagBase = reinterpret_cast<BYTE const*>(&diag);
		switch (diag.CallerType) {
			case 0:
				source.Kind = PowerRequester::Driver;
				source.Name = StringAt(diagBase, diag.Device.DeviceDescriptionOffset, end);
				source.DevicePath = StringAt(diagBase, diag.Device.DevicePathOffset, end);
				break;

			default:
				source.Kind = diag.CallerType == 2 ? PowerRequester::Service : PowerRequester::Process;
				source.Name = StringAt(diagBase, diag.Process.ProcessImageNameOffset, end);
				if (source.Name.starts_with(L"\\Device\\"))
					if (auto dos = dosNames.Convert(source.Name); !dos.empty())
						source.Name = dos;
				source.ProcessId = diag.Process.ProcessId;
				if (source.Kind == PowerRequester::Service)
					source.ServiceName = ServiceFromTag(diag.Process.ProcessId, diag.Process.ServiceTag);
				break;
		}
		source.Reason = ReasonText(diagBase, diag.ReasonOffset, end);
	}
}

bool PowerRequest::IsActive() const {
	return std::any_of(std::begin(Counts), std::end(Counts), [](auto c) { return c > 0; });
}

PCWSTR PowerRequests::TypeName(PowerRequestType type) {
	switch (type) {
		case PowerRequestType::Display: return L"Display";
		case PowerRequestType::System: return L"System";
		case PowerRequestType::AwayMode: return L"Away mode";
		case PowerRequestType::Execution: return L"Execution";
		case PowerRequestType::PerfBoost: return L"Performance boost";
		case PowerRequestType::ActiveLockScreen: return L"Active lock screen";
	}
	return L"";
}

std::optional<std::vector<PowerRequest>> PowerRequests::Enum(bool activeOnly) {
	auto buffer = Query(GetPowerRequestListLevel);
	if (!buffer)
		return std::nullopt;
	auto base = buffer->data();
	auto end = base + buffer->size();
	auto count = *reinterpret_cast<ULONG_PTR const*>(base);
	auto offsets = reinterpret_cast<ULONG_PTR const*>(base + sizeof(ULONG_PTR));
	if (sizeof(ULONG_PTR) * (count + 1) > buffer->size())
		return std::vector<PowerRequest>();
	DosNames dosNames;
	std::vector<PowerRequest> requests;
	for (ULONG_PTR i = 0; i < count; i++) {
		if (offsets[i] + sizeof(RequestV4) > buffer->size())
			continue;
		auto& raw = *reinterpret_cast<RequestV4 const*>(base + offsets[i]);
		// an entry's strings stay before the next entry
		auto entryEnd = i + 1 < count && offsets[i + 1] > offsets[i] ? base + offsets[i + 1] : end;
		PowerRequest request;
		for (int t = 0; t < (int)PowerRequestType::_Count; t++)
			request.Counts[t] = raw.Counts[t];
		if (activeOnly && !request.IsActive())
			continue;
		ReadSource(request, raw.Diag, entryEnd, dosNames);
		requests.push_back(std::move(request));
	}
	return requests;
}

std::optional<std::vector<WakeTimer>> PowerRequests::EnumWakeTimers() {
	auto buffer = Query(WakeTimerListLevel);
	if (!buffer)
		return std::nullopt;
	auto base = buffer->data();
	auto end = base + buffer->size();
	FILETIME now;
	::GetSystemTimeAsFileTime(&now);
	auto nowTime = (int64_t)ULARGE_INTEGER{ now.dwLowDateTime, now.dwHighDateTime }.QuadPart;
	DosNames dosNames;
	std::vector<WakeTimer> timers;
	// an empty list is one entry with nothing in it
	for (auto p = base; p + sizeof(WakeTimerInfo) <= end; ) {
		auto& raw = *reinterpret_cast<WakeTimerInfo const*>(p);
		auto entryEnd = raw.OffsetToNext ? p + raw.OffsetToNext : end;
		if (raw.Diag.Size) {
			WakeTimer timer;
			timer.DueTime = nowTime + raw.DueTime.QuadPart;
			timer.PeriodMs = raw.Period;
			ReadSource(timer, raw.Diag, (std::min)(entryEnd, end), dosNames);
			timers.push_back(std::move(timer));
		}
		if (!raw.OffsetToNext)
			break;
		p += raw.OffsetToNext;
	}
	return timers;
}

std::optional<TimerResolution> PowerRequests::GetTimerResolution() {
	TimerResolution resolution;
	ULONG coarsest, finest, current;
	auto status = ::NtQueryTimerResolution(&coarsest, &finest, &current);
	if (!NT_SUCCESS(status)) {
		::SetLastError(::RtlNtStatusToDosError(status));
		return std::nullopt;
	}
	resolution.Coarsest = coarsest;
	resolution.Finest = finest;
	resolution.Current = current;
	return resolution;
}
