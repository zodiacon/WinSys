#pragma once

#include <unordered_set>

namespace WinSys {
	//
	// Which processes run .NET, without opening them: a .NET Framework CLR creates a section named after its process
	// (Cor_Private_IPCBlock[_v4]_<pid>) in the process's session's namespace, and .NET Core and later runtimes listen on
	// a diagnostics pipe named dotnet-diagnostic-<pid>-... (unless DOTNET_EnableDiagnostics=0). Both appear after the
	// process starts, once the runtime does.
	//
	struct DotNetInfo final abstract {
		// whether the process's section of a .NET Framework CLR exists (another user's counts, though it can't be opened)
		[[nodiscard]] static bool HasFrameworkRuntime(uint32_t pid, uint32_t sessionId);
		// the processes with a .NET Core (or later) runtime's diagnostics pipe
		[[nodiscard]] static std::unordered_set<uint32_t> GetCoreRuntimeProcesses();
	};
}
