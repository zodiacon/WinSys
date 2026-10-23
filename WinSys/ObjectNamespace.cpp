#include "pch.h"
#include "ObjectNamespace.h"
#include <wil/resource.h>

using namespace WinSys;

namespace {
	struct ObjectName {
		explicit ObjectName(std::wstring const& path) {
			::RtlInitUnicodeString(&Name, path.c_str());
			InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		}
		UNICODE_STRING Name;
		OBJECT_ATTRIBUTES Attributes;
	};

	DWORD Fail(NTSTATUS status) {
		auto error = ::RtlNtStatusToDosError(status);
		::SetLastError(error);
		return error;
	}
}

std::wstring ObjectNamespace::Join(std::wstring const& directory, std::wstring const& name) {
	return directory.ends_with(L'\\') ? directory + name : directory + L'\\' + name;
}

std::optional<std::vector<NamespaceEntry>> ObjectNamespace::EnumDirectory(std::wstring const& path) {
	ObjectName name(path);
	wil::unique_handle hDirectory;
	if (auto status = ::NtOpenDirectoryObject(hDirectory.addressof(), DIRECTORY_QUERY, &name.Attributes); !NT_SUCCESS(status)) {
		Fail(status);
		return std::nullopt;
	}

	std::vector<NamespaceEntry> entries;
	auto buffer = std::make_unique<BYTE[]>(1 << 16);
	ULONG context = 0;
	for (bool first = true;; first = false) {
		ULONG size;
		auto start = context;
		auto status = ::NtQueryDirectoryObject(hDirectory.get(), buffer.get(), 1 << 16, FALSE, first, &context, &size);
		if (status == STATUS_NO_MORE_ENTRIES)
			break;
		if (!NT_SUCCESS(status)) {
			Fail(status);
			return std::nullopt;
		}
		auto info = reinterpret_cast<OBJECT_DIRECTORY_INFORMATION const*>(buffer.get());
		for (ULONG i = 0; i < context - start && info[i].Name.Buffer; i++)
			entries.push_back({ std::wstring(info[i].Name.Buffer, info[i].Name.Length / sizeof(WCHAR)),
				std::wstring(info[i].TypeName.Buffer, info[i].TypeName.Length / sizeof(WCHAR)) });
		// STATUS_MORE_ENTRIES: the buffer held only some; anything else, the last of them
		if (status != STATUS_MORE_ENTRIES)
			break;
	}
	return entries;
}

std::optional<SymbolicLinkInfo> ObjectNamespace::GetSymbolicLink(std::wstring const& path) {
	ObjectName name(path);
	wil::unique_handle hLink;
	if (auto status = ::NtOpenSymbolicLinkObject(hLink.addressof(), SYMBOLIC_LINK_QUERY, &name.Attributes); !NT_SUCCESS(status)) {
		Fail(status);
		return std::nullopt;
	}
	SymbolicLinkInfo info;
	std::wstring target(1024, L'\0');
	for (int i = 0; i < 2; i++) {
		UNICODE_STRING result{ 0, (USHORT)(target.size() * sizeof(WCHAR)), target.data() };
		ULONG needed = 0;
		auto status = ::NtQuerySymbolicLinkObject(hLink.get(), &result, &needed);
		if (status == STATUS_BUFFER_TOO_SMALL && needed && i == 0) {
			target.resize(needed / sizeof(WCHAR) + 1);
			continue;
		}
		if (NT_SUCCESS(status))
			info.Target.assign(result.Buffer, result.Length / sizeof(WCHAR));
		break;
	}
	OBJECT_BASIC_INFORMATION basic;
	if (NT_SUCCESS(::NtQueryObject(hLink.get(), ObjectBasicInformation, &basic, sizeof(basic), nullptr)))
		info.CreateTime = basic.CreationTime.QuadPart;
	return info;
}

bool ObjectNamespace::CanOpen(std::wstring const& type) {
	static PCWSTR const types[] = { L"Directory", L"SymbolicLink", L"Event", L"Mutant", L"Semaphore", L"Section", L"Timer",
		L"IoCompletion", L"Job", L"Key", L"Session", L"EventPair" };
	return std::ranges::find(types, type) != std::end(types);
}

HANDLE ObjectNamespace::Open(std::wstring const& path, std::wstring const& type, uint32_t access) {
	ObjectName name(path);
	auto attr = &name.Attributes;
	HANDLE h = nullptr;
	NTSTATUS status;
	if (type == L"Directory")
		status = ::NtOpenDirectoryObject(&h, access, attr);
	else if (type == L"SymbolicLink")
		status = ::NtOpenSymbolicLinkObject(&h, access, attr);
	else if (type == L"Event")
		status = ::NtOpenEvent(&h, access, attr);
	else if (type == L"Mutant")
		status = ::NtOpenMutant(&h, access, attr);
	else if (type == L"Semaphore")
		status = ::NtOpenSemaphore(&h, access, attr);
	else if (type == L"Section")
		status = ::NtOpenSection(&h, access, attr);
	else if (type == L"Timer")
		status = ::NtOpenTimer(&h, access, attr);
	else if (type == L"IoCompletion")
		status = ::NtOpenIoCompletion(&h, access, attr);
	else if (type == L"Job")
		status = ::NtOpenJobObject(&h, access, attr);
	else if (type == L"Key")
		status = ::NtOpenKey(&h, access, attr);
	else if (type == L"Session")
		status = ::NtOpenSession(&h, access, attr);
	else if (type == L"EventPair")
		status = ::NtOpenEventPair(&h, access, attr);
	else {
		::SetLastError(ERROR_NOT_SUPPORTED);
		return nullptr;
	}
	if (!NT_SUCCESS(status)) {
		Fail(status);
		return nullptr;
	}
	return h;
}

std::optional<uint32_t> ObjectNamespace::GetHandleCount(std::wstring const& path, std::wstring const& type) {
	// no access is enough for the basic information; some objects can't be opened even so
	wil::unique_handle h(Open(path, type, 0));
	if (!h)
		h.reset(Open(path, type, MAXIMUM_ALLOWED));
	if (!h)
		return std::nullopt;
	OBJECT_BASIC_INFORMATION basic;
	if (!NT_SUCCESS(::NtQueryObject(h.get(), ObjectBasicInformation, &basic, sizeof(basic), nullptr)))
		return std::nullopt;
	return basic.HandleCount ? basic.HandleCount - 1 : 0;
}

std::optional<HandleEntry> ObjectNamespace::Describe(HANDLE handle) {
	OBJECT_BASIC_INFORMATION basic;
	if (!NT_SUCCESS(::NtQueryObject(handle, ObjectBasicInformation, &basic, sizeof(basic), nullptr)))
		return std::nullopt;
	// the type's information is followed by its name
	BYTE buffer[1024];
	auto type = reinterpret_cast<OBJECT_TYPE_INFORMATION const*>(buffer);
	if (!NT_SUCCESS(::NtQueryObject(handle, ObjectTypeInformation, buffer, sizeof(buffer), nullptr)))
		return std::nullopt;
	HandleEntry entry{};
	entry.Value = (uint64_t)(ULONG_PTR)handle;
	entry.Access = basic.GrantedAccess;
	entry.Attributes = basic.Attributes;
	entry.TypeIndex = type->TypeIndex;
	return entry;
}
