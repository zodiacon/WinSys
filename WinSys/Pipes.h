#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// The named pipes and mailslots there are, from their file systems' root directories (\Device\NamedPipe\ and
// \Device\Mailslot\, NtQueryDirectoryFile). A pipe's directory entry has its instance counts: the end of file is the
// current instances, the allocation size the most allowed. Nothing is opened but the roots: opening a pipe would
// connect to it as a client, taking one of its server's listening instances. No elevation needed.
//
namespace WinSys {
	struct PipeEntry {
		std::wstring Name;	// below the root: "lsass", "LOCAL\..."; a mailslot's may have backslashes
		bool Mailslot{ false };
		// pipes only; MaxInstances -1: unlimited
		int64_t Instances{ 0 }, MaxInstances{ 0 };
		int64_t Created{ 0 };	// FILETIME: a mailslot's; the named pipe file system reports no times (0)

		// "\\.\pipe\<name>" or "\\.\mailslot\<name>", as CreateFile takes it
		[[nodiscard]] std::wstring Win32Path() const;
	};

	struct Pipes final {
		// nothing (with the last error set) if the root can't be listed
		[[nodiscard]] static std::optional<std::vector<PipeEntry>> EnumPipes();
		[[nodiscard]] static std::optional<std::vector<PipeEntry>> EnumMailslots();
	};
}
