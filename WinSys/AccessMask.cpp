#include "pch.h"
#include "AccessMask.h"
#include <algorithm>
#include <vector>
#include <bit>

using namespace WinSys;

namespace {
	struct Right {
		uint32_t Mask;
		PCWSTR Name;
	};

	struct TypeRights {
		PCWSTR Type;
		uint32_t AllAccess;
		// combinations first (they include standard rights, which two of them can share), then the single rights
		std::vector<Right> Rights;
	};

	const std::vector<TypeRights> s_Types = {
		{ L"Process", PROCESS_ALL_ACCESS, {
			{ 0x0001, L"TERMINATE" }, { 0x0002, L"CREATE_THREAD" }, { 0x0004, L"SET_SESSIONID" }, { 0x0008, L"VM_OPERATION" },
			{ 0x0010, L"VM_READ" }, { 0x0020, L"VM_WRITE" }, { 0x0040, L"DUP_HANDLE" }, { 0x0080, L"CREATE_PROCESS" },
			{ 0x0100, L"SET_QUOTA" }, { 0x0200, L"SET_INFORMATION" }, { 0x0400, L"QUERY_INFORMATION" },
			{ 0x0800, L"SUSPEND_RESUME" }, { 0x1000, L"QUERY_LIMITED_INFORMATION" }, { 0x2000, L"SET_LIMITED_INFORMATION" } } },
		{ L"Thread", THREAD_ALL_ACCESS, {
			{ 0x0001, L"TERMINATE" }, { 0x0002, L"SUSPEND_RESUME" }, { 0x0004, L"ALERT" }, { 0x0008, L"GET_CONTEXT" },
			{ 0x0010, L"SET_CONTEXT" }, { 0x0020, L"SET_INFORMATION" }, { 0x0040, L"QUERY_INFORMATION" },
			{ 0x0080, L"SET_THREAD_TOKEN" }, { 0x0100, L"IMPERSONATE" }, { 0x0200, L"DIRECT_IMPERSONATION" },
			{ 0x0400, L"SET_LIMITED_INFORMATION" }, { 0x0800, L"QUERY_LIMITED_INFORMATION" }, { 0x1000, L"RESUME" } } },
		{ L"File", FILE_ALL_ACCESS, {
			{ FILE_GENERIC_READ, L"GENERIC_READ" }, { FILE_GENERIC_WRITE, L"GENERIC_WRITE" },
			{ 0x0001, L"READ_DATA" }, { 0x0002, L"WRITE_DATA" }, { 0x0004, L"APPEND_DATA" }, { 0x0008, L"READ_EA" },
			{ 0x0010, L"WRITE_EA" }, { 0x0020, L"EXECUTE" }, { 0x0040, L"DELETE_CHILD" }, { 0x0080, L"READ_ATTRIBUTES" },
			{ 0x0100, L"WRITE_ATTRIBUTES" } } },
		{ L"Key", KEY_ALL_ACCESS, {
			{ KEY_READ, L"READ" }, { KEY_WRITE, L"WRITE" },
			{ 0x0001, L"QUERY_VALUE" }, { 0x0002, L"SET_VALUE" }, { 0x0004, L"CREATE_SUB_KEY" },
			{ 0x0008, L"ENUMERATE_SUB_KEYS" }, { 0x0010, L"NOTIFY" }, { 0x0020, L"CREATE_LINK" },
			{ 0x0100, L"WOW64_64KEY" }, { 0x0200, L"WOW64_32KEY" } } },
		{ L"Event", EVENT_ALL_ACCESS, { { 0x0001, L"QUERY_STATE" }, { 0x0002, L"MODIFY_STATE" } } },
		{ L"Mutant", MUTANT_ALL_ACCESS, { { 0x0001, L"QUERY_STATE" } } },
		{ L"Semaphore", SEMAPHORE_ALL_ACCESS, { { 0x0001, L"QUERY_STATE" }, { 0x0002, L"MODIFY_STATE" } } },
		{ L"Timer", TIMER_ALL_ACCESS, { { 0x0001, L"QUERY_STATE" }, { 0x0002, L"MODIFY_STATE" } } },
		{ L"IRTimer", TIMER_ALL_ACCESS, { { 0x0001, L"QUERY_STATE" }, { 0x0002, L"MODIFY_STATE" } } },
		{ L"IoCompletion", 0x1F0003, { { 0x0001, L"QUERY_STATE" }, { 0x0002, L"MODIFY_STATE" } } },
		{ L"Section", SECTION_ALL_ACCESS, {
			{ 0x0001, L"QUERY" }, { 0x0002, L"MAP_WRITE" }, { 0x0004, L"MAP_READ" }, { 0x0008, L"MAP_EXECUTE" },
			{ 0x0010, L"EXTEND_SIZE" }, { 0x0020, L"MAP_EXECUTE_EXPLICIT" } } },
		{ L"Token", TOKEN_ALL_ACCESS, {
			{ 0x0001, L"ASSIGN_PRIMARY" }, { 0x0002, L"DUPLICATE" }, { 0x0004, L"IMPERSONATE" }, { 0x0008, L"QUERY" },
			{ 0x0010, L"QUERY_SOURCE" }, { 0x0020, L"ADJUST_PRIVILEGES" }, { 0x0040, L"ADJUST_GROUPS" },
			{ 0x0080, L"ADJUST_DEFAULT" }, { 0x0100, L"ADJUST_SESSIONID" } } },
		{ L"Directory", 0xF000F, {
			{ 0x0001, L"QUERY" }, { 0x0002, L"TRAVERSE" }, { 0x0004, L"CREATE_OBJECT" }, { 0x0008, L"CREATE_SUBDIRECTORY" } } },
		{ L"SymbolicLink", 0xF0001, { { 0x0001, L"QUERY" } } },
		// not an object type: the SCM's services, for an ACL editor
		{ L"Service", SERVICE_ALL_ACCESS, {
			{ 0x0001, L"QUERY_CONFIG" }, { 0x0002, L"CHANGE_CONFIG" }, { 0x0004, L"QUERY_STATUS" }, { 0x0008, L"ENUMERATE_DEPENDENTS" },
			{ 0x0010, L"START" }, { 0x0020, L"STOP" }, { 0x0040, L"PAUSE_CONTINUE" }, { 0x0080, L"INTERROGATE" },
			{ 0x0100, L"USER_DEFINED_CONTROL" } } },
		{ L"Job", JOB_OBJECT_ALL_ACCESS, {
			{ 0x0001, L"ASSIGN_PROCESS" }, { 0x0002, L"SET_ATTRIBUTES" }, { 0x0004, L"QUERY" }, { 0x0008, L"TERMINATE" },
			{ 0x0010, L"SET_SECURITY_ATTRIBUTES" }, { 0x0020, L"IMPERSONATE" } } },
		{ L"WindowStation", 0xF037F, {
			{ 0x0001, L"ENUMDESKTOPS" }, { 0x0002, L"READATTRIBUTES" }, { 0x0004, L"ACCESSCLIPBOARD" },
			{ 0x0008, L"CREATEDESKTOP" }, { 0x0010, L"WRITEATTRIBUTES" }, { 0x0020, L"ACCESSGLOBALATOMS" },
			{ 0x0040, L"EXITWINDOWS" }, { 0x0100, L"ENUMERATE" }, { 0x0200, L"READSCREEN" } } },
		{ L"Desktop", 0xF01FF, {
			{ 0x0001, L"READOBJECTS" }, { 0x0002, L"CREATEWINDOW" }, { 0x0004, L"CREATEMENU" }, { 0x0008, L"HOOKCONTROL" },
			{ 0x0010, L"JOURNALRECORD" }, { 0x0020, L"JOURNALPLAYBACK" }, { 0x0040, L"ENUMERATE" },
			{ 0x0080, L"WRITEOBJECTS" }, { 0x0100, L"SWITCHDESKTOP" } } },
		{ L"ALPC Port", 0x1F0001, { { 0x0001, L"CONNECT" } } },
		{ L"TpWorkerFactory", 0xF00FF, {
			{ 0x0001, L"RELEASE_WORKER" }, { 0x0002, L"WAIT" }, { 0x0004, L"SET_INFORMATION" },
			{ 0x0008, L"QUERY_INFORMATION" }, { 0x0010, L"READY_WORKER" }, { 0x0020, L"SHUTDOWN" } } },
		{ L"Session", 0xF0003, { { 0x0001, L"QUERY" }, { 0x0002, L"MODIFY" } } },
	};

	const Right s_Standard[] = {
		{ DELETE, L"DELETE" }, { READ_CONTROL, L"READ_CONTROL" }, { WRITE_DAC, L"WRITE_DAC" },
		{ WRITE_OWNER, L"WRITE_OWNER" }, { SYNCHRONIZE, L"SYNCHRONIZE" },
		{ ACCESS_SYSTEM_SECURITY, L"ACCESS_SYSTEM_SECURITY" }, { MAXIMUM_ALLOWED, L"MAXIMUM_ALLOWED" },
		{ GENERIC_ALL, L"GENERIC_ALL" }, { GENERIC_EXECUTE, L"GENERIC_EXECUTE" }, { GENERIC_WRITE, L"GENERIC_WRITE" },
		{ GENERIC_READ, L"GENERIC_READ" },
	};
}

std::wstring AccessMaskDecoder::Decode(std::wstring const& type, uint32_t access) {
	if (access == 0)
		return L"";
	auto it = std::ranges::find_if(s_Types, [&](auto& t) { return type == t.Type; });
	if (it != s_Types.end() && (access & it->AllAccess) == it->AllAccess)
		return access == it->AllAccess ? L"ALL_ACCESS" : L"ALL_ACCESS | " + Decode(L"", access & ~it->AllAccess);

	std::wstring text;
	auto add = [&](PCWSTR name) {
		if (!text.empty())
			text += L" | ";
		text += name;
	};
	auto left = access;
	if (it != s_Types.end()) {
		for (auto& r : it->Rights) {
			// against the whole mask, so combinations that share bits all match; each adds bits not shown yet
			if ((access & r.Mask) == r.Mask && (left & r.Mask)) {
				add(r.Name);
				left &= ~r.Mask;
			}
		}
	}
	for (auto& r : s_Standard) {
		if ((left & r.Mask) == r.Mask) {
			add(r.Name);
			left &= ~r.Mask;
		}
	}
	if (left) {
		WCHAR hex[16];
		::StringCchPrintf(hex, _countof(hex), L"0x%X", left);
		add(hex);
	}
	return text;
}

std::vector<AccessRight> AccessMaskDecoder::GetSpecificRights(std::wstring const& type) {
	std::vector<AccessRight> rights;
	auto it = std::ranges::find_if(s_Types, [&](auto& t) { return type == t.Type; });
	if (it != s_Types.end())
		for (auto& r : it->Rights)
			if ((r.Mask & ~SPECIFIC_RIGHTS_ALL) == 0 && std::has_single_bit(r.Mask))
				rights.push_back({ r.Mask, r.Name });
	return rights;
}

std::vector<AccessRight> AccessMaskDecoder::GetStandardRights() {
	std::vector<AccessRight> rights;
	for (auto& r : s_Standard)
		if (r.Mask & STANDARD_RIGHTS_ALL)
			rights.push_back({ r.Mask, r.Name });
	return rights;
}
