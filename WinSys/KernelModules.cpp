#include "pch.h"
#include "KernelModules.h"
#include "Helpers.h"
#include "SystemInfo.h"

using namespace WinSys;

namespace {
	// once: most modules need it, on every enumeration
	std::wstring const& SystemRoot() {
		static std::wstring const root = [] {
			WCHAR path[MAX_PATH];
			auto len = ::GetSystemWindowsDirectory(path, _countof(path));
			return std::wstring(len > 0 && len < _countof(path) ? path : L"C:\\Windows");
		}();
		return root;
	}

	// the kernel's names are ANSI
	std::wstring ToWide(std::string const& text) {
		std::wstring result(text.size(), L'\0');
		result.resize(::MultiByteToWideChar(CP_ACP, 0, text.data(), (int)text.size(), result.data(), (int)result.size()));
		return result;
	}
}

std::wstring KernelModules::ToWin32Path(std::wstring const& path) {
	if (::_wcsnicmp(path.c_str(), L"\\SystemRoot\\", 12) == 0)
		return SystemRoot() + path.substr(11);
	if (path.starts_with(L"\\??\\"))
		return path.substr(4);
	if (::_wcsnicmp(path.c_str(), L"\\Device\\", 8) == 0) {
		auto dos = Helpers::GetDosNameFromNtName(path.c_str());
		return dos.empty() ? path : dos;
	}
	// "\Windows\..." is on the system drive
	if (path.starts_with(L"\\") && !path.starts_with(L"\\\\"))
		return SystemRoot().substr(0, 2) + path;
	return path;
}

std::wstring KernelModules::DriverImagePath(std::wstring const& serviceName, std::wstring const& imagePath) {
	if (imagePath.empty())
		return SystemRoot() + L"\\System32\\drivers\\" + serviceName + L".sys";
	// neither rooted nor with a drive: under the system root
	if (imagePath[0] != L'\\' && (imagePath.size() < 2 || imagePath[1] != L':'))
		return SystemRoot() + L"\\" + imagePath;
	return ToWin32Path(imagePath);
}

namespace {
	KernelModule ToModule(RTL_PROCESS_MODULE_INFORMATION const& info, std::string const& fullPath, std::string const& fileName) {
		KernelModule module;
		module.Path = KernelModules::ToWin32Path(ToWide(fullPath));
		module.Name = ToWide(fileName);
		module.Base = (uint64_t)info.ImageBase;
		module.Size = info.ImageSize;
		module.LoadOrder = info.LoadOrderIndex;
		module.InitOrder = info.InitOrderIndex;
		module.LoadCount = info.LoadCount;
		module.Flags = info.Flags;
		return module;
	}
}

std::vector<KernelModule> KernelModules::Enum() {
	std::vector<KernelModule> result;
	if (auto modules = SystemInfo::GetKernelModuleInformationEx(); !modules.empty()) {
		result.reserve(modules.size());
		for (auto& m : modules) {
			auto module = ToModule(m.Info.BaseInfo, m.FullPath, m.FileName);
			module.TimeDateStamp = m.Info.TimeDateStamp;
			module.Checksum = m.Info.ImageChecksum;
			module.DefaultBase = (uint64_t)m.Info.DefaultBase;
			result.push_back(std::move(module));
		}
		return result;
	}
	auto modules = SystemInfo::GetKernelModuleInformation();
	result.reserve(modules.size());
	for (auto& m : modules)
		result.push_back(ToModule(m.Info, m.FullPath, m.FileName));
	return result;
}
