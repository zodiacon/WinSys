#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <wil/resource.h>

namespace WinSys {
	struct StackFrameAddress {
		uint64_t Address;
		bool Is32Bit;	// a WOW64 thread's 32-bit frame (they follow its native frames)
	};

	enum class ModuleSymbolsKind {
		NotLoaded,	// not looked for yet (deferred loads: an address in it hasn't been resolved)
		None,		// no symbols found: addresses show as module+offset
		Exports,	// the module's exports only (no PDB found)
		Pdb,
		Other,		// COFF, CodeView, .sym...
	};

	struct ModuleSymbols {
		std::wstring ImagePath;		// the module's file
		std::wstring SymbolFile;	// where its symbols came from (the PDB); empty for exports or none
		ModuleSymbolsKind Kind{ ModuleSymbolsKind::NotLoaded };
	};

	//
	// Symbols through DbgHelp: a session for a process (DbgHelp's on its handle, invaded with deferred loads: the module
	// list is read, symbols are loaded when needed) or for the kernel's modules (at their bases from
	// SystemModuleInformation, which only an elevated caller gets). DbgHelp isn't thread-safe: one thread must make all
	// the calls to it, through every handler and MiniDump. The caller loads the dbghelp.dll to use (with symsrv.dll
	// beside it for symbol servers) before the first call, and calls SetOptions once.
	//
	class SymbolHandler final {
	public:
		// undecorated names, deferred loads, source lines, a WOW64 process's 32-bit modules, no prompts
		static void SetOptions();
		[[nodiscard]] static bool IsKernelAddress(uint64_t address);

		// the process, opened with query and VM read access; null (with the last error) if it can't be opened, or if
		// created (non-zero) isn't its creation time (another process with the ID: ERROR_INVALID_PARAMETER)
		[[nodiscard]] static std::unique_ptr<SymbolHandler> ForProcess(uint32_t pid, int64_t created, std::wstring const& searchPath);
		// the kernel's modules; null if their bases aren't known (not elevated). One at a time: its DbgHelp session has
		// a fixed key
		[[nodiscard]] static std::unique_ptr<SymbolHandler> ForKernel(std::wstring const& searchPath);
		~SymbolHandler();
		SymbolHandler(SymbolHandler const&) = delete;
		SymbolHandler& operator=(SymbolHandler const&) = delete;

		// "module!function+0x10", "module+0x1234", or empty if the address is in no known module; the module list is read
		// again (at most every 2 s) for an address in none. source: "file(line)" when the symbols have line numbers
		std::wstring GetSymbol(uint64_t address, std::wstring* source = nullptr);
		// the symbols of the module the address is in, as far as they were loaded (GetSymbol loads them); nullopt if the
		// address is in no known module
		[[nodiscard]] std::optional<ModuleSymbols> GetModuleSymbols(uint64_t address) const;

		// a thread's user-mode stack, innermost first (a WOW64 thread's native frames, then its 32-bit ones): the thread
		// is suspended only to get its context and copy its stack, and the walk (which may load symbols) reads the copy.
		// Not for the calling process's threads, which could deadlock. false (with the last error) if the thread can't be
		// opened, suspended or have its context read
		bool CaptureStack(uint32_t tid, std::vector<StackFrameAddress>& frames);

		[[nodiscard]] bool IsKernel() const;

	private:
		SymbolHandler() = default;
		HANDLE Session() const;
		bool LoadKernelModules();

		wil::unique_handle m_Process;	// none for the kernel's
		bool m_Wow64{ false };
		ULONGLONG m_LastRefresh{ 0 };
	};

	struct MiniDump final {
		// writes a dump of the process (created, non-zero: its creation time, checked); full: all its memory, else threads,
		// modules, handles and the memory map. false (with the last error) on failure, and the file is removed
		static bool Write(uint32_t pid, int64_t created, std::wstring const& path, bool full, uint64_t& size);
	};
}
