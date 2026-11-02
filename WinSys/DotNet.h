#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

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

	// what a .NET Core (or later) runtime says of its process over its diagnostics pipe (ProcessInfo2, else ProcessInfo)
	struct DotNetCoreProcessInfo {
		uint64_t ProcessId{ 0 };
		GUID RuntimeCookie{};
		std::wstring CommandLine, Os, Architecture;
		std::wstring EntryAssembly;	// ProcessInfo2's (.NET 6 and later); empty from ProcessInfo
		std::wstring ClrVersion;	// "8.0.10+81cabf2857a01351e5ab578947c7403a5b128ad1"; empty from ProcessInfo
	};

	// a process's garbage collections, as DotNetGcMonitor saw them since it started
	struct DotNetGcStats {
		uint32_t Collections{ 0 };
		uint32_t ByGeneration[3]{};	// collections of generation 0, 1, 2
		uint32_t LastGeneration{ 0 }, LastReason{ 0 };	// GCStart's depth and reason
		bool HasHeap{ false };		// a GCHeapStats seen: the sizes below are the last collection's
		uint64_t GenerationSize[3]{}, LohSize{ 0 }, PohSize{ 0 };
		uint32_t PinnedObjects{ 0 }, GcHandles{ 0 };
		uint64_t LastPause{ 0 }, MaxPause{ 0 }, TotalPause{ 0 };	// the runtime suspended, 100 ns units
		int64_t SuspendStart{ 0 };	// a suspension in progress (its time stamp), else 0
		[[nodiscard]] uint64_t HeapSize() const;	// the generations and the large and pinned object heaps
	};

	//
	// Follows a process's garbage collections with a real-time ETW session ("<sessionPrefix><this process's ID>.<n>")
	// on Microsoft-Windows-DotNETRuntime's GC keyword for that process only: GCStart (the collections by generation and
	// reason), GCHeapStats (the generations' sizes after each), GCSuspendEEBegin and GCRestartEEEnd (the pauses). Both the
	// .NET Framework's CLR and CoreCLR report them. Needs elevation; nothing comes until the next collection.
	//
	class DotNetGcMonitor {
	public:
		~DotNetGcMonitor();
		// false (the last error set) if the session can't be started or the provider enabled
		bool Start(uint32_t pid, PCWSTR sessionPrefix);
		void Stop();
		[[nodiscard]] bool IsRunning() const;
		// the stats so far; Flush first delivers the session's buffers (it flushes every second by itself)
		[[nodiscard]] DotNetGcStats GetStats() const;
		void Flush();
		// one GC event's payload (by its ID and version, at its 100 ns time stamp) added to stats, the parsing apart for
		// the tests: GCStart (1), GCRestartEEEnd (3), GCHeapStats (4), GCSuspendEEBegin (9); false if it isn't one or is
		// cut short
		static bool ApplyGcEvent(uint16_t eventId, uint8_t version, uint8_t const* data, size_t size, int64_t timeStamp, DotNetGcStats& stats);

		struct State;	// internal (public for the callback, which is the .cpp's)

	private:
		State* m_State{ nullptr };
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
		// the process's diagnostics pipe ("dotnet-diagnostic-<pid>"), empty if it has none
		[[nodiscard]] static std::wstring FindDiagnosticsPipe(uint32_t pid);
		// What the process's .NET Core (or later) runtime says over its diagnostics pipe: the diagnostics IPC protocol's
		// ProcessInfo2 (the runtime's version and the entry assembly; .NET 6 and later), else ProcessInfo. No elevation: the
		// pipe lets in its process's user (and administrators). Waits at most timeoutMs for the answer (a suspended process
		// doesn't give one). Nothing, with the last error set, if there's no pipe or no answer
		[[nodiscard]] static std::optional<DotNetCoreProcessInfo> QueryCoreProcessInfo(uint32_t pid, uint32_t timeoutMs = 2000);
		// a ProcessInfo (v2: ProcessInfo2) answer's payload, the parsing apart for the tests; nothing if it's cut short
		[[nodiscard]] static std::optional<DotNetCoreProcessInfo> ParseProcessInfo(uint8_t const* payload, size_t size, bool v2);
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
		// one rundown event's payload added to details, by its ID and version (QueryProcess's parsing, apart for the tests):
		// RuntimeInformationDCStart (187), AppDomainDCStart (157), AssemblyDCStart (155), ModuleDCStart (153), DCStartComplete
		// (145, whose runtimes go to completed); a truncated payload adds nothing. True when every runtime is complete
		static bool ApplyRundownEvent(uint16_t eventId, uint8_t version, uint8_t const* data, size_t size, DotNetProcessDetails& details,
			std::vector<uint16_t>& completed);
	};
}
