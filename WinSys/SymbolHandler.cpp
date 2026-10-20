#include "pch.h"
#include "SymbolHandler.h"
#include "KernelModules.h"
#define _NO_CVCONST_H
#include <DbgHelp.h>
#include <algorithm>

#pragma comment(lib, "dbghelp")

using namespace WinSys;

namespace {
	// a stack copy is at most this much of the stack, from the stack pointer up
	const size_t MaxStackCopy = 1 << 20;
	const int MaxFrames = 256;
	// a module list is read again when an address is in none of its modules, at most this often
	const ULONGLONG ModuleRefreshInterval = 2000;
	// stands for the kernel in DbgHelp, which takes any value as a process handle when it doesn't invade the process
	HANDLE const KernelSession = (HANDLE)(ULONG_PTR)0x4B524E4C;


	bool CheckCreated(HANDLE hProcess, int64_t created) {
		FILETIME time, exited, kernel, user;
		if (created && ::GetProcessTimes(hProcess, &time, &exited, &kernel, &user)
			&& (int64_t)ULARGE_INTEGER{ time.dwLowDateTime, time.dwHighDateTime }.QuadPart != created) {
			::SetLastError(ERROR_INVALID_PARAMETER);
			return false;
		}
		return true;
	}

	// the stack copies the walk reads from instead of the process (the one DbgHelp thread walks one stack at a time)
	struct StackCopy {
		uint64_t Base;
		std::vector<BYTE> Bytes;
	};
	thread_local std::vector<StackCopy> const* t_Stacks;

	BOOL CALLBACK ReadMemory(HANDLE hProcess, DWORD64 address, PVOID buffer, DWORD size, LPDWORD read) {
		if (t_Stacks)
			for (auto& copy : *t_Stacks)
				if (address >= copy.Base && address + size <= copy.Base + copy.Bytes.size()) {
					memcpy(buffer, copy.Bytes.data() + (address - copy.Base), size);
					*read = size;
					return TRUE;
				}
		SIZE_T bytes = 0;
		auto ok = ::ReadProcessMemory(hProcess, (void const*)address, buffer, size, &bytes);
		*read = (DWORD)bytes;
		return ok || bytes > 0;
	}

	// "module!function+0x10", "module+0x1234", or empty if the address is in no known module
	std::wstring Format(HANDLE hSession, uint64_t address, std::wstring* source) {
		IMAGEHLP_MODULEW64 module{ sizeof(module) };
		if (!::SymGetModuleInfoW64(hSession, address, &module))
			return L"";
		auto slash = wcsrchr(module.ImageName, L'\\');
		std::wstring name = slash ? slash + 1 : module.ImageName;
		if (name.empty())
			name = module.ModuleName;

		BYTE buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
		auto symbol = reinterpret_cast<SYMBOL_INFOW*>(buffer);
		symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
		symbol->MaxNameLen = MAX_SYM_NAME;
		DWORD64 displacement = 0;
		std::wstring text;
		// no std::format in WinSys: its format_error is an exception class (see ProcessNameLookup in Handles.h)
		auto hex = [](DWORD64 value) {
			WCHAR text[24];
			::StringCchPrintf(text, _countof(text), L"+0x%llX", value);
			return std::wstring(text);
		};
		if (::SymFromAddrW(hSession, address, &displacement, symbol))
			text = name + L"!" + symbol->Name + (displacement ? hex(displacement) : L"");
		else
			text = name + hex(address - module.BaseOfImage);

		if (source) {
			IMAGEHLP_LINEW64 line{ sizeof(line) };
			DWORD lineDisplacement;
			if (::SymGetLineFromAddrW64(hSession, address, &lineDisplacement, &line))
				*source = std::wstring(line.FileName) + L"(" + std::to_wstring(line.LineNumber) + L")";
		}
		return text;
	}
}

void SymbolHandler::SetOptions() {
	::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS |
		SYMOPT_LOAD_LINES | SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_OMAP_FIND_NEAREST);
}

bool SymbolHandler::IsKernelAddress(uint64_t address) {
	return (int64_t)address < 0;
}

std::unique_ptr<SymbolHandler> SymbolHandler::ForProcess(uint32_t pid, int64_t created, std::wstring const& searchPath) {
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
	if (!hProcess || !CheckCreated(hProcess.get(), created))
		return nullptr;
	// invading reads the module list; with deferred loads, symbols are loaded only when they're needed
	if (!::SymInitializeW(hProcess.get(), searchPath.c_str(), TRUE))
		return nullptr;
	std::unique_ptr<SymbolHandler> handler(new SymbolHandler);
	BOOL wow64 = FALSE;
	::IsWow64Process(hProcess.get(), &wow64);
	handler->m_Wow64 = wow64;
	handler->m_Process = std::move(hProcess);
	handler->m_LastRefresh = ::GetTickCount64();
	return handler;
}

std::unique_ptr<SymbolHandler> SymbolHandler::ForKernel(std::wstring const& searchPath) {
	if (!::SymInitializeW(KernelSession, searchPath.c_str(), FALSE))
		return nullptr;
	std::unique_ptr<SymbolHandler> handler(new SymbolHandler);
	if (!handler->LoadKernelModules())
		return nullptr;	// its destructor cleans the session up
	return handler;
}

SymbolHandler::~SymbolHandler() {
	::SymCleanup(Session());
}

HANDLE SymbolHandler::Session() const {
	return m_Process ? m_Process.get() : KernelSession;
}

bool SymbolHandler::IsKernel() const {
	return !m_Process;
}

std::optional<ModuleSymbols> SymbolHandler::GetModuleSymbols(uint64_t address) const {
	IMAGEHLP_MODULEW64 module{ sizeof(module) };
	if (!::SymGetModuleInfoW64(Session(), address, &module))
		return std::nullopt;
	ModuleSymbols symbols;
	symbols.ImagePath = module.LoadedImageName[0] ? module.LoadedImageName : module.ImageName;
	switch (module.SymType) {
		case SymDeferred: symbols.Kind = ModuleSymbolsKind::NotLoaded; break;
		case SymNone: symbols.Kind = ModuleSymbolsKind::None; break;
		case SymExport: symbols.Kind = ModuleSymbolsKind::Exports; break;
		case SymPdb: case SymDia: symbols.Kind = ModuleSymbolsKind::Pdb; break;
		default: symbols.Kind = ModuleSymbolsKind::Other; break;
	}
	if (symbols.Kind == ModuleSymbolsKind::Pdb || symbols.Kind == ModuleSymbolsKind::Other)
		symbols.SymbolFile = module.LoadedPdbName;
	return symbols;
}

bool SymbolHandler::LoadKernelModules() {
	m_LastRefresh = ::GetTickCount64();
	auto modules = KernelModules::Enum();
	// without elevation, the bases are zero
	if (modules.empty() || !modules[0].Base)
		return false;
	// a module already loaded fails, which is fine: drivers loaded since are added
	for (auto& m : modules)
		::SymLoadModuleExW(KernelSession, nullptr, m.Path.c_str(), nullptr, m.Base, m.Size, nullptr, 0);
	return true;
}

std::wstring SymbolHandler::GetSymbol(uint64_t address, std::wstring* source) {
	auto text = Format(Session(), address, source);
	if (text.empty() && ::GetTickCount64() - m_LastRefresh >= ModuleRefreshInterval) {
		// a module loaded since the list was read
		if (m_Process) {
			m_LastRefresh = ::GetTickCount64();
			::SymRefreshModuleList(m_Process.get());
		}
		else
			LoadKernelModules();
		text = Format(Session(), address, source);
	}
	return text;
}

bool SymbolHandler::CaptureStack(uint32_t tid, std::vector<StackFrameAddress>& frames) {
	frames.clear();
	auto hProcess = m_Process.get();
	if (!hProcess) {
		::SetLastError(ERROR_INVALID_FUNCTION);
		return false;
	}
	wil::unique_handle hThread(::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
	if (!hThread)
		return false;

	// the stack's top is in the TEB (NT_TIB); a WOW64 thread's 32-bit TEB is two pages after the 64-bit one
	THREAD_BASIC_INFORMATION tbi{};
	NT_TIB tib{};
	if (NT_SUCCESS(::NtQueryInformationThread(hThread.get(), ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)))
		::ReadProcessMemory(hProcess, tbi.TebBaseAddress, &tib, sizeof(tib), nullptr);
	NT_TIB32 tib32{};
	if (m_Wow64 && tbi.TebBaseAddress)
		::ReadProcessMemory(hProcess, (BYTE const*)tbi.TebBaseAddress + 0x2000, &tib32, sizeof(tib32), nullptr);

	// suspended only for the context and a copy of the stack: the walk (which may load symbols) runs on the copy
	std::vector<StackCopy> stacks;
	auto copyStack = [&](uint64_t sp, uint64_t base) {
		if (!sp || base <= sp)
			return;
		StackCopy copy{ sp };
		copy.Bytes.resize((size_t)(std::min)(base - sp, (uint64_t)MaxStackCopy));
		SIZE_T read = 0;
		::ReadProcessMemory(hProcess, (void const*)sp, copy.Bytes.data(), copy.Bytes.size(), &read);
		copy.Bytes.resize(read);
		stacks.push_back(std::move(copy));
	};
	CONTEXT context{};
	context.ContextFlags = CONTEXT_FULL;
#ifdef _M_X64
	WOW64_CONTEXT context32{};
	context32.ContextFlags = WOW64_CONTEXT_FULL;
	bool have32 = false;
#endif
	if (::SuspendThread(hThread.get()) == (DWORD)-1)
		return false;
	bool ok = ::GetThreadContext(hThread.get(), &context);
	auto error = ::GetLastError();
	if (ok) {
#if defined(_M_X64)
		copyStack(context.Rsp, (uint64_t)tib.StackBase);
		if (m_Wow64 && ::Wow64GetThreadContext(hThread.get(), &context32)) {
			have32 = true;
			copyStack(context32.Esp, tib32.StackBase);
		}
#elif defined(_M_ARM64)
		copyStack(context.Sp, (uint64_t)tib.StackBase);
#else
		copyStack(context.Esp, (uint64_t)tib.StackBase);
#endif
	}
	::ResumeThread(hThread.get());
	if (!ok) {
		::SetLastError(error);
		return false;
	}

	t_Stacks = &stacks;
	auto walk = [&](DWORD machine, void* contextRecord, uint64_t pc, uint64_t frame, uint64_t sp, bool is32) {
		STACKFRAME_EX sf{};
		sf.StackFrameSize = sizeof(sf);
		sf.AddrPC.Offset = pc;
		sf.AddrPC.Mode = AddrModeFlat;
		sf.AddrFrame.Offset = frame;
		sf.AddrFrame.Mode = AddrModeFlat;
		sf.AddrStack.Offset = sp;
		sf.AddrStack.Mode = AddrModeFlat;
		uint64_t previous = 0;
		for (int i = 0; i < MaxFrames; i++) {
			if (!::StackWalkEx(machine, hProcess, hThread.get(), &sf, contextRecord, ReadMemory, ::SymFunctionTableAccess64,
				::SymGetModuleBase64, nullptr, SYM_STKWALK_DEFAULT))
				break;
			if (sf.AddrPC.Offset == 0 || (i > 0 && sf.AddrPC.Offset == previous && sf.AddrStack.Offset == sp))
				break;
			previous = sf.AddrPC.Offset;
			sp = sf.AddrStack.Offset;
			frames.push_back({ sf.AddrPC.Offset, is32 });
		}
	};
#if defined(_M_X64)
	walk(IMAGE_FILE_MACHINE_AMD64, &context, context.Rip, context.Rsp, context.Rsp, false);
	if (have32)
		walk(IMAGE_FILE_MACHINE_I386, &context32, context32.Eip, context32.Ebp, context32.Esp, true);
#elif defined(_M_ARM64)
	walk(IMAGE_FILE_MACHINE_ARM64, &context, context.Pc, context.Fp, context.Sp, false);
#else
	walk(IMAGE_FILE_MACHINE_I386, &context, context.Eip, context.Ebp, context.Esp, false);
#endif
	t_Stacks = nullptr;
	return true;
}

bool MiniDump::Write(uint32_t pid, int64_t created, std::wstring const& path, bool full, uint64_t& size) {
	size = 0;
	// the handles' data needs PROCESS_DUP_HANDLE
	wil::unique_handle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pid));
	if (!hProcess || !CheckCreated(hProcess.get(), created))
		return false;
	wil::unique_hfile file(::CreateFile(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!file)
		return false;
	auto type = MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithThreadInfo | MiniDumpWithProcessThreadData
		| MiniDumpWithFullMemoryInfo;
	if (full)
		type |= MiniDumpWithFullMemory | MiniDumpWithTokenInformation | MiniDumpIgnoreInaccessibleMemory;
	if (!::MiniDumpWriteDump(hProcess.get(), pid, file.get(), (MINIDUMP_TYPE)type, nullptr, nullptr, nullptr)) {
		auto error = ::GetLastError();
		file.reset();
		::DeleteFile(path.c_str());
		// MiniDumpWriteDump returns an HRESULT as the last error
		::SetLastError(HRESULT_FACILITY(error) == FACILITY_WIN32 ? HRESULT_CODE(error) : error);
		return false;
	}
	LARGE_INTEGER fileSize;
	if (::GetFileSizeEx(file.get(), &fileSize))
		size = fileSize.QuadPart;
	return true;
}
