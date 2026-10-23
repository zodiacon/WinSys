#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "Handles.h"

//
// The object manager's namespace, as WinObj shows it: directories (NtOpenDirectoryObject, NtQueryDirectoryObject),
// symbolic links (NtQuerySymbolicLinkObject) and the named objects in them, opened by name through their type's own open
// function. Without elevation, some directories can't be listed and many objects can't be opened.
//

namespace WinSys {
	struct NamespaceEntry {
		std::wstring Name, TypeName;
	};

	struct SymbolicLinkInfo {
		std::wstring Target;
		int64_t CreateTime{ 0 };	// FILETIME (the link's, from its basic information)
	};

	struct ObjectNamespace final {
		// a directory's entries, in the directory's order; nothing if it can't be opened or read, with the last error
		[[nodiscard]] static std::optional<std::vector<NamespaceEntry>> EnumDirectory(std::wstring const& path);
		// a symbolic link's target; nothing if it can't be opened, with the last error
		[[nodiscard]] static std::optional<SymbolicLinkInfo> GetSymbolicLink(std::wstring const& path);
		// Opens a named object through its type's open function: Directory, SymbolicLink, Event, Mutant, Semaphore,
		// Section, Timer, IoCompletion, Job, Key, Session and EventPair (devices and files aren't opened: opening a
		// device can have effects). Null with the last error otherwise (ERROR_NOT_SUPPORTED for other types)
		[[nodiscard]] static HANDLE Open(std::wstring const& path, std::wstring const& type, uint32_t access);
		// whether Open knows the type
		[[nodiscard]] static bool CanOpen(std::wstring const& type);
		// the object's handle count, not counting the handle opened to read it; nothing if it can't be opened
		[[nodiscard]] static std::optional<uint32_t> GetHandleCount(std::wstring const& path, std::wstring const& type);
		// a handle of this process as the system's handle table would list it (access, attributes, type index), so the
		// handle inspectors can take it; nothing if it can't be queried
		[[nodiscard]] static std::optional<HandleEntry> Describe(HANDLE handle);
		// a directory's path joined with a name in it
		[[nodiscard]] static std::wstring Join(std::wstring const& directory, std::wstring const& name);
	};
}
