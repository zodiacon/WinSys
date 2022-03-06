#pragma once

#include <string>

namespace WinSys {
	struct KernelModuleInfo {
		std::string Name;
		std::string FullPath;
		HANDLE hSection;
		void* MappedBase;
		void* ImageBase;
		uint32_t ImageSize;
		uint32_t Flags;
		uint16_t LoadOrderIndex;
		uint16_t InitOrderIndex;
		uint16_t LoadCount;
		void* DefaultBase;
		uint32_t ImageChecksum;
		uint32_t TimeDateStamp;
	};

	class KernelModuleTracker final {
	public:
		uint32_t EnumModules();

		std::vector<std::shared_ptr<KernelModuleInfo>> const& GetModules() const;
		std::vector<std::shared_ptr<KernelModuleInfo>> const& GetNewModules() const;
		std::vector<std::shared_ptr<KernelModuleInfo>> const& GetUnloadedModules() const;

	private:
		std::vector<std::shared_ptr<KernelModuleInfo>> m_modules, m_newModules, m_unloadedModules;
		const std::unordered_map<void*, std::shared_ptr<KernelModuleInfo>> m_moduleMap;
	};
}
