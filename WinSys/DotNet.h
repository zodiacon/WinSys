#pragma once

#include <unordered_set>

namespace WinSys {
	// a runtime in the process (two CLRs can run side by side in a .NET Framework process)
	struct DotNetRuntime {
		uint16_t ClrInstanceId{ 0 };
		bool Core{ false };	// CoreCLR (.NET Core, .NET 5 and later), else the .NET Framework's CLR
		std::wstring Version;	// the runtime's (VM) file version, "8.0.1024.46610"
		std::wstring BclVersion;	// the base class library's
		std::wstring RuntimePath;	// clr.dll or coreclr.dll
		std::wstring CommandLine;	// as the runtime saw it
		uint32_t StartupFlags{ 0 };
	};

	struct DotNetAppDomain {
		uint64_t Id{ 0 };
		uint32_t Flags{ 0 };	// DotNetAppDomainFlags
		uint32_t Index{ 0 };
		std::wstring Name;
	};

	enum class DotNetAppDomainFlags : uint32_t {
		Default = 1, Executable = 2, Shared = 4,
	};

	struct DotNetAssembly {
		uint64_t Id{ 0 };
		uint64_t AppDomainId{ 0 };
		uint32_t Flags{ 0 };	// DotNetAssemblyFlags
		std::wstring FullName;	// "Name, Version=..., Culture=..., PublicKeyToken=..."
	};

	enum class DotNetAssemblyFlags : uint32_t {
		DomainNeutral = 1, Dynamic = 2, Native = 4, Collectible = 8, ReadyToRun = 0x10,
	};

	struct DotNetModule {
		uint64_t Id{ 0 };
		uint64_t AssemblyId{ 0 };
		uint32_t Flags{ 0 };	// DotNetModuleFlags
		std::wstring ILPath;	// empty for a dynamic module
		std::wstring NativePath;	// the native image (NGen), if any
	};

	enum class DotNetModuleFlags : uint32_t {
		DomainNeutral = 1, Native = 2, Dynamic = 4, Manifest = 8, IbcOptimized = 0x10, ReadyToRun = 0x20, PartialReadyToRun = 0x40,
	};

	struct DotNetProcessDetails {
		std::vector<DotNetRuntime> Runtimes;
		std::vector<DotNetAppDomain> AppDomains;
		std::vector<DotNetAssembly> Assemblies;
		std::vector<DotNetModule> Modules;
		bool Complete{ false };	// every runtime said its rundown was done (else the timeout ended it)
	};

	//
	// Which processes run .NET, without opening them: a .NET Framework CLR creates a section named after its process
	// (Cor_Private_IPCBlock[_v4]_<pid>) in the process's session's namespace, and .NET Core and later runtimes listen on
	// a diagnostics pipe named dotnet-diagnostic-<pid>-... (unless DOTNET_EnableDiagnostics=0). Both appear after the
	// process starts, once the runtime does.
	//
	struct DotNetInfo final {
		// whether the process's section of a .NET Framework CLR exists (another user's counts, though it can't be opened);
		// found for the 2.0 CLR and older 4.x ones only (see HasRuntimeModule)
		[[nodiscard]] static bool HasFrameworkRuntime(uint32_t pid, uint32_t sessionId);
		// the processes with a .NET Core (or later) runtime's diagnostics pipe
		[[nodiscard]] static std::unordered_set<uint32_t> GetCoreRuntimeProcesses();
		// whether a runtime's DLL is loaded in the process (clr.dll, .NET Framework 4; mscorwks.dll, 2.0 to 3.5; coreclr.dll),
		// for when the cheaper checks above miss it: the .NET Framework 4 CLR on current Windows creates its section in a
		// private namespace, where HasFrameworkRuntime doesn't look. Needs PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
		[[nodiscard]] static bool HasRuntimeModule(uint32_t pid);

		// The process's runtimes, AppDomains, assemblies and modules, from the runtime's own rundown: a real-time ETW session
		// ("<sessionPrefix><this process's ID>.<n>"; orphaned ones are stopped) enables Microsoft-Windows-DotNETRuntimeRundown
		// for the process only (a PID filter) with the loader and start rundown keywords, and the runtime reports what it
		// has loaded, ending with DCStartComplete. Both the .NET Framework's CLR and CoreCLR do. Blocks until every runtime
		// is done (about half a second: the session is flushed every 250 ms while waiting), the timeout or the cancel event
		// (optional) is signaled. Enabling the provider needs elevation (ERROR_ACCESS_DENIED otherwise); a process without a
		// runtime (or with diagnostics disabled) gives an empty result once the timeout passes. Failures set the last error.
		[[nodiscard]] static std::optional<DotNetProcessDetails> QueryProcess(uint32_t pid, PCWSTR sessionPrefix,
			uint32_t timeoutMs = 10000, HANDLE hCancel = nullptr);
	};
}
