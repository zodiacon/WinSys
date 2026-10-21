#include "pch.h"
#include "ProcessModuleTracker.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <ImageHlp.h>
#include "Helpers.h"
#include "ProcessMemory.h"

#pragma comment(lib, "imagehlp")

using namespace WinSys;

struct ProcessModuleTracker::Impl {
	std::vector<std::shared_ptr<ModuleInfo>> _modules, _newModules, _unloadedModules;
	std::unordered_map<std::wstring, std::shared_ptr<ModuleInfo>> _moduleMap;
	DWORD _pid;
	wil::unique_handle _handle;
	BOOL _isWow64;

	explicit Impl(DWORD pid) : _pid(pid) {
		_handle.reset(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid));
		if (_handle)
			::IsWow64Process(_handle.get(), &_isWow64);
	}

	explicit Impl(HANDLE hProcess) : _handle(hProcess) {
		::IsWow64Process(_handle.get(), &_isWow64);
	}

	const std::vector<std::shared_ptr<ModuleInfo>>& GetModules() const {
		return _modules;
	}

	const std::vector<std::shared_ptr<ModuleInfo>>& GetNewModules() const {
		return _newModules;
	}

	const std::vector<std::shared_ptr<ModuleInfo>>& GetUnloadedModules() const {
		return _unloadedModules;
	}

	std::shared_ptr<ModuleInfo> FillModule(const MODULEENTRY32& me) {
		auto mi = std::make_shared<ModuleInfo>();
		mi->Name = me.szModule;
		mi->Path = me.szExePath;
		mi->Base = (void*)me.hModule;
		mi->ImageBase = nullptr;
		mi->ModuleSize = me.modBaseSize;
		mi->Characteristics = DllCharacteristics::None;
		mi->Type = MapType::Image;
		return mi;
	}

	// a new module: the PE header (preferred base and DLL characteristics) is read once
	std::shared_ptr<ModuleInfo> FillModule(const MEMORY_BASIC_INFORMATION& mbi, std::wstring const& ntPath) {
		auto mi = std::make_shared<ModuleInfo>();
		mi->ModuleSize = 0;
		mi->ImageBase = nullptr;
		mi->Characteristics = DllCharacteristics::None;
		if (!ntPath.empty()) {
			mi->Path = Helpers::GetDosNameFromNtName(ntPath.c_str());
			auto bs = ntPath.rfind(L'\\');
			mi->Name = bs == std::wstring::npos ? ntPath : ntPath.substr(bs + 1);
		}
		mi->Base = mbi.AllocationBase;
		mi->Type = mbi.Type == MEM_MAPPED ? MapType::Data : MapType::Image;
		if (mi->Type == MapType::Image) {
			BYTE buffer[1 << 12];
			if (::ReadProcessMemory(_handle.get(), mbi.BaseAddress, buffer, sizeof(buffer), nullptr)) {
				auto nt = ::ImageNtHeader(buffer);
				if (nt) {
					auto machine = nt->FileHeader.Machine;
					if (machine == IMAGE_FILE_MACHINE_ARM || machine == IMAGE_FILE_MACHINE_I386) {
						auto oh = (IMAGE_OPTIONAL_HEADER32*)&nt->OptionalHeader;
						mi->ImageBase = UlongToPtr(oh->ImageBase);
						mi->Characteristics = (DllCharacteristics)oh->DllCharacteristics;
					}
					else {
						mi->ImageBase = (PVOID)nt->OptionalHeader.ImageBase;
						mi->Characteristics = (DllCharacteristics)nt->OptionalHeader.DllCharacteristics;
					}
				}
			}
		}
		return mi;
	}

	uint32_t EnumModules() {
		return _handle ? EnumModulesWithVirtualQuery() : EnumModulesWithToolHelp();
	}

	// Each call builds the module list again from what's mapped now (in address order), keeping the objects of
	// modules that were already there; the ones that are gone become the unloaded modules.
	void Update(std::vector<std::shared_ptr<ModuleInfo>> modules, std::unordered_map<std::wstring, std::shared_ptr<ModuleInfo>> map) {
		_unloadedModules.clear();
		for (auto& [key, mi] : _moduleMap)
			if (!map.contains(key))
				_unloadedModules.push_back(mi);
		_modules = std::move(modules);
		_moduleMap = std::move(map);
	}

	uint32_t EnumModulesWithVirtualQuery() {
		_newModules.clear();
		std::vector<std::shared_ptr<ModuleInfo>> modules;
		modules.reserve(_modules.empty() ? 128 : _modules.size() + 8);
		std::unordered_map<std::wstring, std::shared_ptr<ModuleInfo>> map;
		map.reserve(modules.capacity());

		MEMORY_BASIC_INFORMATION mbi;
		const BYTE* address = nullptr;
		ModuleInfo* current = nullptr;	// the module the regions belong to (an allocation's regions are contiguous)
		void* currentBase = nullptr;
		while (::VirtualQueryEx(_handle.get(), address, &mbi, sizeof(mbi)) > 0) {
			if (mbi.State == MEM_COMMIT && mbi.Type != MEM_PRIVATE) {
				if (mbi.AllocationBase != currentBase) {
					// the start of a mapping (an image or a data file); the key tells a module from another at the same
					// address after an unload and a load
					currentBase = mbi.AllocationBase;
					// not GetMappedFileName's MAX_PATH buffer: a longer name was cut
					auto ntPath = ProcessMemory::GetMappedFileName(_handle.get(), mbi.AllocationBase);
					auto key = ntPath + L"#" + std::to_wstring((size_t)mbi.AllocationBase);
					std::shared_ptr<ModuleInfo> mi;
					if (auto it = _moduleMap.find(key); it != _moduleMap.end())
						mi = it->second;
					else {
						mi = FillModule(mbi, ntPath);
						_newModules.push_back(mi);
					}
					mi->ModuleSize = 0;
					current = mi.get();
					map.insert({ key, mi });
					modules.push_back(std::move(mi));
				}
				current->ModuleSize += (ULONG)mbi.RegionSize;
			}
			address += mbi.RegionSize;
		}
		Update(std::move(modules), std::move(map));
		return static_cast<uint32_t>(_modules.size());
	}

	uint32_t EnumModulesWithToolHelp() {
		wil::unique_handle hSnapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, _pid));
		if (!hSnapshot || hSnapshot.get() == INVALID_HANDLE_VALUE) {
			hSnapshot.release();
			return 0;
		}

		_newModules.clear();
		std::vector<std::shared_ptr<ModuleInfo>> modules;
		std::unordered_map<std::wstring, std::shared_ptr<ModuleInfo>> map;
		MODULEENTRY32 me;
		me.dwSize = sizeof(me);
		if (::Module32First(hSnapshot.get(), &me)) {
			do {
				auto key = std::wstring(me.szExePath) + L"#" + std::to_wstring((size_t)me.hModule);
				std::shared_ptr<ModuleInfo> mi;
				if (auto it = _moduleMap.find(key); it != _moduleMap.end())
					mi = it->second;
				else {
					mi = FillModule(me);
					_newModules.push_back(mi);
				}
				map.insert({ key, mi });
				modules.push_back(std::move(mi));
			} while (::Module32Next(hSnapshot.get(), &me));
		}
		Update(std::move(modules), std::move(map));
		return static_cast<uint32_t>(_modules.size());
	}
};

ProcessModuleTracker::~ProcessModuleTracker() = default;

ProcessModuleTracker::ProcessModuleTracker(DWORD pid) : _impl(new Impl(pid)) {
}

ProcessModuleTracker::ProcessModuleTracker(HANDLE hProcess) : _impl(new Impl(hProcess)) {
}

uint32_t ProcessModuleTracker::EnumModules() {
	return _impl->EnumModules();
}

const std::vector<std::shared_ptr<ModuleInfo>>& ProcessModuleTracker::GetModules() const {
	return _impl->GetModules();
}

const std::vector<std::shared_ptr<ModuleInfo>>& ProcessModuleTracker::GetNewModules() const {
	return _impl->GetNewModules();
}

const std::vector<std::shared_ptr<ModuleInfo>>& ProcessModuleTracker::GetUnloadedModules() const {
	return _impl->GetUnloadedModules();
}

bool ProcessModuleTracker::IsRunning() const {
	return ::WaitForSingleObject(_impl->_handle.get(), 0) == WAIT_TIMEOUT;
}
