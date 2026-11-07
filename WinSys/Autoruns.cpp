#include "pch.h"
#include "Autoruns.h"
#include "KernelModules.h"
#include "ServiceManager.h"
#include "Packages.h"
#include <taskschd.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <xmllite.h>
#include <ctime>
#include <wil/com.h>
#include <wil/resource.h>

#pragma comment(lib, "taskschd")
#pragma comment(lib, "shlwapi")
#pragma comment(lib, "xmllite")

using namespace WinSys;

namespace {
	constexpr PCWSTR ApprovedKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\";
	// a package's state per user (HKCU): a startup task's under <family name>\<task ID>
	constexpr PCWSTR AppDataKey = L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\";

	// Windows.ApplicationModel.StartupTaskState, the State value
	enum StartupTaskState : DWORD {
		TaskDisabled = 0, TaskDisabledByUser = 1, TaskEnabled = 2, TaskDisabledByPolicy = 3, TaskEnabledByPolicy = 4,
	};

	std::wstring Lowercase(std::wstring text) {
		::CharLowerBuffW(text.data(), (DWORD)text.size());
		return text;
	}

	bool EndsWith(std::wstring const& text, PCWSTR suffix) {
		auto len = wcslen(suffix);
		return text.size() >= len && _wcsicmp(text.c_str() + text.size() - len, suffix) == 0;
	}

	std::wstring Trim(std::wstring text) {
		auto first = text.find_first_not_of(L" \t\r\n");
		if (first == std::wstring::npos)
			return {};
		auto last = text.find_last_not_of(L" \t\r\n");
		return text.substr(first, last - first + 1);
	}

	std::wstring Expand(std::wstring const& text) {
		if (text.find(L'%') == std::wstring::npos)
			return text;
		auto size = ::ExpandEnvironmentStringsW(text.c_str(), nullptr, 0);
		if (size == 0)
			return text;
		std::wstring result(size, L'\0');
		::ExpandEnvironmentStringsW(text.c_str(), result.data(), size);
		result.resize(wcslen(result.c_str()));
		return result;
	}

	bool IsFile(std::wstring const& path) {
		auto attributes = ::GetFileAttributesW(path.c_str());
		return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
	}

	std::wstring SystemRoot() {
		WCHAR dir[MAX_PATH];
		return ::GetWindowsDirectoryW(dir, _countof(dir)) ? dir : L"C:\\Windows";
	}

	int64_t ToInt64(FILETIME const& ft) {
		return ((int64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	}

	// a path as typed: under the system root when relative ("system32\x.exe"), else found on the search path
	std::wstring FindFile(std::wstring path, PCWSTR extension) {
		if (path.empty())
			return path;
		if (_wcsnicmp(path.c_str(), L"\\SystemRoot\\", 12) == 0)
			path = SystemRoot() + path.substr(11);
		else if (path.starts_with(L"\\??\\"))
			path = path.substr(4);
		if (IsFile(path))
			return path;
		if (extension && IsFile(path + extension))
			return path + extension;
		bool rooted = path[0] == L'\\' || (path.size() > 1 && path[1] == L':');
		if (!rooted && path.find(L'\\') != std::wstring::npos) {
			auto full = SystemRoot() + L"\\" + path;
			if (IsFile(full))
				return full;
		}
		if (path.find(L'\\') == std::wstring::npos) {
			WCHAR found[MAX_PATH];
			if (::SearchPathW(nullptr, path.c_str(), extension, _countof(found), found, nullptr))
				return found;
		}
		return path;
	}

	// the first token: quoted, or the longest run of words that names a file (an unquoted path with spaces)
	std::wstring FirstPath(std::wstring const& text, size_t& rest, PCWSTR extension) {
		if (text.empty())
			return {};
		if (text[0] == L'"') {
			auto end = text.find(L'"', 1);
			if (end == std::wstring::npos)
				end = text.size();
			rest = end + 1 < text.size() ? end + 1 : text.size();
			return FindFile(text.substr(1, end - 1), extension);
		}
		size_t pos = 0;
		std::wstring first;
		size_t firstEnd = text.size();
		while (true) {
			auto space = text.find(L' ', pos);
			auto candidate = text.substr(0, space);
			if (first.empty()) {
				first = candidate;
				firstEnd = space == std::wstring::npos ? text.size() : space;
			}
			if (IsFile(candidate) || (extension && IsFile(candidate + extension)) ||
				(candidate.size() > 1 && candidate[1] == L':' && IsFile(FindFile(candidate, extension)))) {
				rest = space == std::wstring::npos ? text.size() : space;
				return FindFile(candidate, extension);
			}
			if (space == std::wstring::npos)
				break;
			pos = space + 1;
		}
		rest = firstEnd;
		return FindFile(first, extension);
	}

	std::wstring FileName(std::wstring const& path) {
		auto slash = path.find_last_of(L"\\/");
		return slash == std::wstring::npos ? path : path.substr(slash + 1);
	}

	struct RegistryValue {
		std::wstring Name;
		DWORD Type{ 0 };
		std::vector<BYTE> Data;

		std::wstring String() const {
			if (Type != REG_SZ && Type != REG_EXPAND_SZ && Type != REG_MULTI_SZ)
				return {};
			std::wstring text((PCWSTR)Data.data(), Data.size() / sizeof(WCHAR));
			text.resize(wcslen(text.c_str()));
			return text;
		}
		std::vector<std::wstring> Strings() const {
			std::vector<std::wstring> items;
			if (Type == REG_MULTI_SZ) {
				auto p = (PCWSTR)Data.data();
				auto end = p + Data.size() / sizeof(WCHAR);
				while (p < end && *p) {
					auto len = wcsnlen(p, end - p);
					items.emplace_back(p, len);
					p += len + 1;
				}
			}
			else if (auto text = String(); !text.empty())
				items.push_back(text);
			return items;
		}
	};

	wil::unique_hkey OpenKey(HKEY root, std::wstring const& subKey, REGSAM access = KEY_READ) {
		HKEY key = nullptr;
		::RegOpenKeyExW(root, subKey.c_str(), 0, access | KEY_WOW64_64KEY, &key);
		return wil::unique_hkey(key);
	}

	int64_t KeyTime(HKEY key) {
		FILETIME ft{};
		return ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS
			? ToInt64(ft) : 0;
	}

	std::optional<RegistryValue> ReadValue(HKEY key, PCWSTR name) {
		DWORD type = 0, size = 0;
		if (::RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
			return {};
		RegistryValue value{ name ? name : L"", type, std::vector<BYTE>(size + sizeof(WCHAR) * 2) };
		if (::RegQueryValueExW(key, name, nullptr, &type, value.Data.data(), &size) != ERROR_SUCCESS)
			return {};
		value.Data.resize(size);
		return value;
	}

	std::optional<DWORD> ReadDword(HKEY key, PCWSTR name) {
		DWORD data = 0, size = sizeof(data), type = 0;
		if (::RegQueryValueExW(key, name, nullptr, &type, (BYTE*)&data, &size) != ERROR_SUCCESS || type != REG_DWORD)
			return {};
		return data;
	}

	std::vector<RegistryValue> ReadValues(HKEY key) {
		std::vector<RegistryValue> values;
		DWORD count = 0, maxName = 0, maxData = 0;
		if (::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &count, &maxName, &maxData, nullptr, nullptr) != ERROR_SUCCESS)
			return values;
		std::wstring name(maxName + 1, L'\0');
		std::vector<BYTE> data(maxData + sizeof(WCHAR) * 2);
		for (DWORD i = 0; ; i++) {
			DWORD nameSize = (DWORD)name.size(), dataSize = (DWORD)data.size(), type = 0;
			auto error = ::RegEnumValueW(key, i, name.data(), &nameSize, nullptr, &type, data.data(), &dataSize);
			if (error == ERROR_NO_MORE_ITEMS)
				break;
			if (error != ERROR_SUCCESS)
				continue;
			values.push_back({ std::wstring(name.c_str(), nameSize), type, std::vector<BYTE>(data.begin(), data.begin() + dataSize) });
		}
		return values;
	}

	std::vector<std::wstring> SubKeys(HKEY key) {
		std::vector<std::wstring> names;
		WCHAR name[256];
		for (DWORD i = 0; ; i++) {
			DWORD size = _countof(name);
			auto error = ::RegEnumKeyExW(key, i, name, &size, nullptr, nullptr, nullptr, nullptr);
			if (error == ERROR_NO_MORE_ITEMS)
				break;
			if (error == ERROR_SUCCESS)
				names.emplace_back(name, size);
		}
		return names;
	}

	std::wstring KeyLocation(HKEY root, std::wstring const& subKey) {
		return std::wstring(Autoruns::RootName(root)) + L"\\" + subKey;
	}

	// Task Manager's Startup apps state: missing or an even first byte is enabled
	bool IsApproved(HKEY root, PCWSTR approved, std::wstring const& name) {
		auto key = OpenKey(root, std::wstring(ApprovedKey) + approved);
		if (!key)
			return true;
		auto value = ReadValue(key.get(), name.c_str());
		return !value || value->Type != REG_BINARY || value->Data.empty() || (value->Data[0] & 1) == 0;
	}

	AutorunEntry RegistryEntry(AutorunCategory category, HKEY root, std::wstring const& subKey, HKEY key, std::wstring const& name,
		std::wstring const& command) {
		AutorunEntry e;
		e.Category = category;
		e.Store = AutorunStore::RegistryValue;
		e.Root = root;
		e.SubKey = subKey;
		e.ValueName = name;
		e.Location = KeyLocation(root, subKey);
		e.Name = name.empty() ? L"(Default)" : name;
		e.Command = command;
		e.ImagePath = Autoruns::ResolveImage(command);
		e.LastModified = KeyTime(key);
		return e;
	}

	void AddRunKeys(std::vector<AutorunEntry>& entries) {
		static const struct {
			HKEY Root;
			PCWSTR SubKey;
			PCWSTR Approved;	// the StartupApproved key, for those Task Manager can disable
			bool Wow64;
		} keys[] = {
			{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"Run", false },
			{ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"Run32", true },
			{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"Run", false },
			{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", nullptr, false },
			{ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", nullptr, true },
			{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", nullptr, false },
			{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", nullptr, false },
			{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", nullptr, false },
		};
		for (auto& k : keys) {
			auto key = OpenKey(k.Root, k.SubKey);
			if (!key)
				continue;
			for (auto& v : ReadValues(key.get())) {
				auto command = v.String();
				if (command.empty())
					continue;
				auto e = RegistryEntry(AutorunCategory::Logon, k.Root, k.SubKey, key.get(), v.Name, command);
				e.Wow64 = k.Wow64;
				e.Deletable = true;
				if (k.Approved)
					e.Enabled = IsApproved(k.Root, k.Approved, v.Name);
				entries.push_back(std::move(e));
			}
		}
	}

	void AddStartupFolders(std::vector<AutorunEntry>& entries) {
		// environment variables rather than the known folder IDs, which the library's INITGUID setup doesn't define
		static const struct {
			PCWSTR Folder;
			HKEY Root;	// whose StartupApproved\StartupFolder
		} folders[] = {
			{ L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", HKEY_CURRENT_USER },
			{ L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", HKEY_LOCAL_MACHINE },
		};
		for (auto& f : folders) {
			auto folder = Expand(f.Folder);
			WIN32_FIND_DATAW fd;
			wil::unique_hfind find(::FindFirstFileW((folder + L"\\*").c_str(), &fd));
			if (!find)
				continue;
			do {
				if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					continue;
				std::wstring name = fd.cFileName;
				if (_wcsicmp(name.c_str(), L"desktop.ini") == 0)
					continue;
				AutorunEntry e;
				e.Category = AutorunCategory::Logon;
				e.Store = AutorunStore::StartupFile;
				e.Location = folder;
				e.Name = name;
				e.Root = f.Root;
				e.ValueName = name;
				e.Deletable = true;
				e.LastModified = ToInt64(fd.ftLastWriteTime);
				e.Enabled = IsApproved(f.Root, L"StartupFolder", name);
				auto path = folder + L"\\" + name;
				if (EndsWith(name, L".lnk")) {
					wil::com_ptr_nothrow<IShellLinkW> link;
					wil::com_ptr_nothrow<IPersistFile> file;
					if (SUCCEEDED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link))) &&
						SUCCEEDED(link->QueryInterface(IID_PPV_ARGS(&file))) && SUCCEEDED(file->Load(path.c_str(), STGM_READ))) {
						WCHAR target[MAX_PATH * 2]{}, args[2048]{};
						link->GetPath(target, _countof(target), nullptr, 0);
						link->GetArguments(args, _countof(args));
						e.ImagePath = Expand(target);
						e.Command = *args ? std::wstring(L"\"") + target + L"\" " + args : std::wstring(target);
						e.Details = args;
					}
				}
				else {
					e.Command = path;
					e.ImagePath = path;
				}
				entries.push_back(std::move(e));
			} while (::FindNextFileW(find.get(), &fd));
		}
	}

	void AddActiveSetup(std::vector<AutorunEntry>& entries) {
		for (auto subKey : { L"Software\\Microsoft\\Active Setup\\Installed Components", L"Software\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components" }) {
			auto key = OpenKey(HKEY_LOCAL_MACHINE, subKey);
			if (!key)
				continue;
			for (auto& name : SubKeys(key.get())) {
				auto componentKey = std::wstring(subKey) + L"\\" + name;
				auto component = OpenKey(HKEY_LOCAL_MACHINE, componentKey);
				if (!component)
					continue;
				if (auto installed = ReadDword(component.get(), L"IsInstalled"); installed && *installed == 0)
					continue;
				auto stub = ReadValue(component.get(), L"StubPath");
				if (!stub || stub->String().empty())
					continue;
				auto e = RegistryEntry(AutorunCategory::Logon, HKEY_LOCAL_MACHINE, componentKey, component.get(), L"StubPath", stub->String());
				// some components have placeholders ("U", "/UserInstall") that run nothing
				if (!IsFile(e.ImagePath))
					continue;
				auto title = ReadValue(component.get(), nullptr);
				e.Name = title && !title->String().empty() ? title->String() : name;
				e.Details = name;
				entries.push_back(std::move(e));
			}
		}
	}

	std::string ReadFileText(std::wstring const& path) {
		wil::unique_hfile file(::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
		LARGE_INTEGER size{};
		if (!file || !::GetFileSizeEx(file.get(), &size) || size.QuadPart > 16 << 20)
			return {};
		std::string text((size_t)size.QuadPart, '\0');
		DWORD read = 0;
		if (!::ReadFile(file.get(), text.data(), (DWORD)text.size(), &read, nullptr))
			return {};
		text.resize(read);
		return text;
	}

	// a manifest's "ms-resource:..." string through the package's resources; empty if it can't be
	std::wstring LoadPackageString(PackageInfo const& package, std::wstring const& text) {
		constexpr PCWSTR scheme = L"ms-resource:";
		if (_wcsnicmp(text.c_str(), scheme, 12) != 0)
			return text;
		auto rest = text.substr(12);
		std::vector<std::wstring> uris;
		if (rest.starts_with(L"//"))
			uris.push_back(text);
		else if (rest.starts_with(L"/"))
			uris.push_back(L"ms-resource://" + package.Name + rest);
		else {
			// a bare name is in the Resources map; a path may name its own map
			uris.push_back(L"ms-resource://" + package.Name + L"/Resources/" + rest);
			if (rest.find(L'/') != std::wstring::npos)
				uris.push_back(L"ms-resource://" + package.Name + L"/" + rest);
		}
		for (auto& uri : uris) {
			auto indirect = L"@{" + package.FullName + L"?" + uri + L"}";
			WCHAR result[512]{};
			if (SUCCEEDED(::SHLoadIndirectString(indirect.c_str(), result, _countof(result), nullptr)) && *result)
				return result;
		}
		return {};
	}

	PCWSTR StartupTaskStateText(DWORD state) {
		switch (state) {
			case TaskDisabled: return L"disabled";
			case TaskDisabledByUser: return L"disabled by the user";
			case TaskEnabled: return L"enabled";
			case TaskDisabledByPolicy: return L"disabled by policy";
			case TaskEnabledByPolicy: return L"enabled by policy";
		}
		return L"unknown state";
	}

	// the current user's packaged apps' startup tasks (Store and MSIX apps: Spotify, Teams...), as Task Manager lists them
	void AddPackageTasks(std::vector<AutorunEntry>& entries) {
		auto packages = Packages::Enum();
		if (!packages)
			return;
		for (auto& p : *packages) {
			if (p.Framework || p.Resource || p.Bundle || p.InstalledPath.empty())
				continue;
			auto manifestPath = p.InstalledPath + L"\\AppxManifest.xml";
			auto manifest = ReadFileText(manifestPath);
			// most packages have none: skip the parse
			if (manifest.find("StartupTask") == std::string::npos)
				continue;
			for (auto& t : Autoruns::ParseStartupTasks(manifest)) {
				AutorunEntry e;
				e.Category = AutorunCategory::Logon;
				e.Store = AutorunStore::PackageTask;
				e.Root = HKEY_CURRENT_USER;
				e.SubKey = std::wstring(AppDataKey) + p.FamilyName + L"\\" + t.TaskId;
				e.ValueName = L"State";
				e.Location = p.FullName;
				e.Name = LoadPackageString(p, t.DisplayName);
				if (e.Name.empty())
					e.Name = !p.DisplayName.empty() ? p.DisplayName : t.TaskId;
				if (!t.Executable.empty()) {
					e.ImagePath = p.InstalledPath + L"\\" + t.Executable;
					e.Command = L"\"" + e.ImagePath + L"\"";
				}
				// the manifest's default until the user or the app sets it
				DWORD state = t.Enabled ? TaskEnabled : TaskDisabled;
				if (auto key = OpenKey(HKEY_CURRENT_USER, e.SubKey)) {
					if (auto value = ReadDword(key.get(), L"State"))
						state = *value;
					e.LastModified = KeyTime(key.get());
				}
				if (e.LastModified == 0) {
					WIN32_FILE_ATTRIBUTE_DATA data;
					if (::GetFileAttributesExW(manifestPath.c_str(), GetFileExInfoStandard, &data))
						e.LastModified = ToInt64(data.ftLastWriteTime);
				}
				e.Enabled = state == TaskEnabled || state == TaskEnabledByPolicy;
				e.Details = L"Startup task " + t.TaskId + L" (" + StartupTaskStateText(state) + L") of " +
					(p.DisplayName.empty() ? p.Name : p.DisplayName);
				entries.push_back(std::move(e));
			}
		}
	}

	void AddWinlogon(std::vector<AutorunEntry>& entries) {
		constexpr PCWSTR winlogon = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
		static const struct {
			HKEY Root;
			PCWSTR Value;
		} values[] = {
			{ HKEY_LOCAL_MACHINE, L"Userinit" }, { HKEY_LOCAL_MACHINE, L"Shell" }, { HKEY_LOCAL_MACHINE, L"Taskman" },
			{ HKEY_LOCAL_MACHINE, L"AppSetup" }, { HKEY_CURRENT_USER, L"Shell" },
		};
		for (auto& v : values) {
			auto key = OpenKey(v.Root, winlogon);
			if (!key)
				continue;
			auto value = ReadValue(key.get(), v.Value);
			if (!value)
				continue;
			// Userinit is a comma-separated list, usually of one
			for (auto& item : value->Strings()) {
				size_t start = 0;
				while (start <= item.size()) {
					auto comma = item.find(L',', start);
					auto command = Trim(item.substr(start, comma == std::wstring::npos ? std::wstring::npos : comma - start));
					if (!command.empty())
						entries.push_back(RegistryEntry(AutorunCategory::Winlogon, v.Root, winlogon, key.get(), v.Value, command));
					if (comma == std::wstring::npos || _wcsicmp(v.Value, L"Userinit") != 0)
						break;
					start = comma + 1;
				}
			}
		}
	}

	void AddAppInit(std::vector<AutorunEntry>& entries) {
		for (auto subKey : { L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" }) {
			auto key = OpenKey(HKEY_LOCAL_MACHINE, subKey);
			if (!key)
				continue;
			auto value = ReadValue(key.get(), L"AppInit_DLLs");
			if (!value)
				continue;
			auto list = value->String();
			// separated by spaces or commas
			size_t pos = 0;
			while (pos < list.size()) {
				auto end = list.find_first_of(L" ,", pos);
				auto dll = list.substr(pos, end == std::wstring::npos ? std::wstring::npos : end - pos);
				if (!dll.empty()) {
					auto e = RegistryEntry(AutorunCategory::AppInit, HKEY_LOCAL_MACHINE, subKey, key.get(), L"AppInit_DLLs", dll);
					e.Name = FileName(dll);
					auto load = ReadDword(key.get(), L"LoadAppInit_DLLs");
					e.Details = load && *load ? L"LoadAppInit_DLLs is on" : L"LoadAppInit_DLLs is off";
					entries.push_back(std::move(e));
				}
				if (end == std::wstring::npos)
					break;
				pos = end + 1;
			}
		}
	}

	void AddBootExecute(std::vector<AutorunEntry>& entries) {
		constexpr PCWSTR subKey = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
		auto key = OpenKey(HKEY_LOCAL_MACHINE, subKey);
		if (!key)
			return;
		for (auto name : { L"BootExecute", L"SetupExecute", L"Execute" }) {
			auto value = ReadValue(key.get(), name);
			if (!value)
				continue;
			for (auto& item : value->Strings()) {
				if (Trim(item).empty())
					continue;
				auto e = RegistryEntry(AutorunCategory::BootExecute, HKEY_LOCAL_MACHINE, subKey, key.get(), name, item);
				// "autocheck autochk *": autocheck says to run it at boot, autochk is the program
				auto program = item;
				if (_wcsnicmp(program.c_str(), L"autocheck ", 10) == 0)
					program = program.substr(10);
				e.ImagePath = Autoruns::ResolveImage(program);
				e.Name = FileName(e.ImagePath.empty() ? item : e.ImagePath);
				e.Details = name;
				entries.push_back(std::move(e));
			}
		}
	}

	void AddLsa(std::vector<AutorunEntry>& entries) {
		for (auto subKey : { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" }) {
			auto key = OpenKey(HKEY_LOCAL_MACHINE, subKey);
			if (!key)
				continue;
			for (auto name : { L"Authentication Packages", L"Notification Packages", L"Security Packages" }) {
				auto value = ReadValue(key.get(), name);
				if (!value)
					continue;
				for (auto item : value->Strings()) {
					item = Trim(item);
					if (item.empty() || item == L"\"\"")
						continue;
					auto e = RegistryEntry(AutorunCategory::Lsa, HKEY_LOCAL_MACHINE, subKey, key.get(), name, item);
					e.Name = item;
					auto dll = item.find(L'.') == std::wstring::npos ? item + L".dll" : item;
					e.ImagePath = FindFile(dll.find(L'\\') == std::wstring::npos ? L"System32\\" + dll : dll, nullptr);
					e.Details = name;
					entries.push_back(std::move(e));
				}
			}
		}
	}

	void AddHijacks(std::vector<AutorunEntry>& entries) {
		static const struct {
			PCWSTR SubKey;
			PCWSTR Value;
		} keys[] = {
			{ L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"Debugger" },
			{ L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"Debugger" },
			{ L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit", L"MonitorProcess" },
		};
		for (auto& k : keys) {
			auto key = OpenKey(HKEY_LOCAL_MACHINE, k.SubKey);
			if (!key)
				continue;
			for (auto& image : SubKeys(key.get())) {
				auto imageKey = std::wstring(k.SubKey) + L"\\" + image;
				auto sub = OpenKey(HKEY_LOCAL_MACHINE, imageKey);
				if (!sub)
					continue;
				auto value = ReadValue(sub.get(), k.Value);
				if (!value || Trim(value->String()).empty())
					continue;
				auto e = RegistryEntry(AutorunCategory::ImageHijack, HKEY_LOCAL_MACHINE, imageKey, sub.get(), k.Value, value->String());
				e.Name = image;
				e.Details = k.Value;
				e.Deletable = true;
				entries.push_back(std::move(e));
			}
		}
	}

	std::wstring MuiString(HKEY key, PCWSTR name) {
		WCHAR text[1024];
		if (::RegLoadMUIStringW(key, name, text, sizeof(text), nullptr, 0, nullptr) == ERROR_SUCCESS)
			return text;
		auto value = ReadValue(key, name);
		return value ? value->String() : L"";
	}

	void AddServices(std::vector<AutorunEntry>& entries) {
		constexpr PCWSTR services = L"SYSTEM\\CurrentControlSet\\Services";
		auto key = OpenKey(HKEY_LOCAL_MACHINE, services);
		if (!key)
			return;
		for (auto& name : SubKeys(key.get())) {
			auto subKey = std::wstring(services) + L"\\" + name;
			auto service = OpenKey(HKEY_LOCAL_MACHINE, subKey);
			if (!service)
				continue;
			auto type = ReadDword(service.get(), L"Type");
			auto start = ReadDword(service.get(), L"Start");
			if (!type || !start || *start > SERVICE_AUTO_START)
				continue;
			bool driver = (*type & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;
			if (!driver && (*type & SERVICE_WIN32) == 0)
				continue;
			AutorunEntry e;
			e.Category = driver ? AutorunCategory::Driver : AutorunCategory::Service;
			e.Store = AutorunStore::Service;
			e.Root = HKEY_LOCAL_MACHINE;
			e.SubKey = subKey;
			e.Location = KeyLocation(HKEY_LOCAL_MACHINE, subKey);
			e.Name = name;
			e.LastModified = KeyTime(service.get());
			auto image = ReadValue(service.get(), L"ImagePath");
			e.Command = image ? image->String() : L"";
			e.Details = MuiString(service.get(), L"DisplayName");
			if (driver)
				e.ImagePath = KernelModules::DriverImagePath(name, Expand(e.Command));
			else {
				e.ImagePath = Autoruns::ResolveImage(e.Command);
				// a shared host's service is its DLL
				if (auto dll = ServiceManager::GetServiceDll(name, (ServiceType)*type); !dll.empty())
					e.ImagePath = FindFile(Expand(dll), nullptr);
			}
			entries.push_back(std::move(e));
		}
	}

	int64_t DateToFileTime(DATE date) {
		if (date <= 1)	// never
			return 0;
		SYSTEMTIME local, utc;
		FILETIME ft;
		if (!::VariantTimeToSystemTime(date, &local) || !::TzSpecificLocalTimeToSystemTime(nullptr, &local, &utc) || !::SystemTimeToFileTime(&utc, &ft))
			return 0;
		return ToInt64(ft);
	}

	// "$(@%SystemRoot%\system32\x.dll,-101)", as tasks' authors and descriptions are often given
	std::wstring Indirect(std::wstring text) {
		if (text.starts_with(L"$(@") && text.ends_with(L")"))
			text = text.substr(2, text.size() - 3);
		if (text.starts_with(L"@")) {
			WCHAR resolved[1024];
			if (SUCCEEDED(::SHLoadIndirectString(text.c_str(), resolved, _countof(resolved), nullptr)))
				return resolved;
		}
		return text;
	}

	std::wstring Bstr(BSTR text) {
		return text ? std::wstring(text, ::SysStringLen(text)) : std::wstring();
	}

	std::wstring AccountName(std::wstring const& id) {
		if (!id.starts_with(L"S-1-"))
			return id;
		PSID sid = nullptr;
		if (!::ConvertStringSidToSidW(id.c_str(), &sid))
			return id;
		WCHAR name[256], domain[256];
		DWORD nameSize = _countof(name), domainSize = _countof(domain);
		SID_NAME_USE use;
		std::wstring result = id;
		if (::LookupAccountSidW(nullptr, sid, name, &nameSize, domain, &domainSize, &use))
			result = *domain ? std::wstring(domain) + L"\\" + name : std::wstring(name);
		::LocalFree(sid);
		return result;
	}

	PCWSTR TriggerName(TASK_TRIGGER_TYPE2 type) {
		switch (type) {
			case TASK_TRIGGER_EVENT: return L"On an event";
			case TASK_TRIGGER_TIME: return L"One time";
			case TASK_TRIGGER_DAILY: return L"Daily";
			case TASK_TRIGGER_WEEKLY: return L"Weekly";
			case TASK_TRIGGER_MONTHLY: case TASK_TRIGGER_MONTHLYDOW: return L"Monthly";
			case TASK_TRIGGER_IDLE: return L"On idle";
			case TASK_TRIGGER_REGISTRATION: return L"At task creation";
			case TASK_TRIGGER_BOOT: return L"At startup";
			case TASK_TRIGGER_LOGON: return L"At log on";
			case TASK_TRIGGER_SESSION_STATE_CHANGE: return L"On session change";
			case TASK_TRIGGER_CUSTOM_TRIGGER_01: return L"Custom";
		}
		return L"Other";
	}

	// a COM handler's in-process server
	std::wstring ComServer(std::wstring const& clsid) {
		auto key = OpenKey(HKEY_CLASSES_ROOT, L"CLSID\\" + clsid + L"\\InprocServer32");
		if (!key)
			return {};
		auto value = ReadValue(key.get(), nullptr);
		return value ? FindFile(Expand(value->String()), nullptr) : L"";
	}

	void ReadTask(IRegisteredTask* task, std::wstring const& folder, std::vector<AutorunEntry>& entries) {
		AutorunEntry e;
		e.Category = AutorunCategory::ScheduledTask;
		e.Store = AutorunStore::Task;
		e.Location = folder;
		e.Deletable = true;
		BSTR text = nullptr;
		if (SUCCEEDED(task->get_Name(&text))) {
			e.Name = Bstr(text);
			::SysFreeString(text);
		}
		if (SUCCEEDED(task->get_Path(&text))) {
			e.TaskPath = Bstr(text);
			::SysFreeString(text);
		}
		VARIANT_BOOL enabled = VARIANT_FALSE;
		if (SUCCEEDED(task->get_Enabled(&enabled)))
			e.Enabled = enabled != VARIANT_FALSE;
		TASK_STATE state;
		if (SUCCEEDED(task->get_State(&state)))
			switch (state) {
				case TASK_STATE_DISABLED: e.TaskState = AutorunTaskState::Disabled; break;
				case TASK_STATE_QUEUED: e.TaskState = AutorunTaskState::Queued; break;
				case TASK_STATE_READY: e.TaskState = AutorunTaskState::Ready; break;
				case TASK_STATE_RUNNING: e.TaskState = AutorunTaskState::Running; break;
			}
		DATE date = 0;
		if (task->get_LastRunTime(&date) == S_OK)
			e.LastRun = DateToFileTime(date);
		if (task->get_NextRunTime(&date) == S_OK)
			e.NextRun = DateToFileTime(date);
		LONG result = 0;
		if (e.LastRun && SUCCEEDED(task->get_LastTaskResult(&result)))
			e.LastResult = result;

		wil::com_ptr_nothrow<ITaskDefinition> definition;
		if (SUCCEEDED(task->get_Definition(&definition))) {
			wil::com_ptr_nothrow<IRegistrationInfo> info;
			if (SUCCEEDED(definition->get_RegistrationInfo(&info))) {
				if (SUCCEEDED(info->get_Author(&text))) {
					e.Author = Indirect(Bstr(text));
					::SysFreeString(text);
				}
				if (SUCCEEDED(info->get_Description(&text))) {
					e.Details = Indirect(Bstr(text));
					::SysFreeString(text);
				}
			}
			wil::com_ptr_nothrow<IPrincipal> principal;
			if (SUCCEEDED(definition->get_Principal(&principal))) {
				if (SUCCEEDED(principal->get_UserId(&text))) {
					e.RunAs = AccountName(Bstr(text));
					::SysFreeString(text);
				}
				if (e.RunAs.empty() && SUCCEEDED(principal->get_GroupId(&text))) {
					e.RunAs = AccountName(Bstr(text));
					::SysFreeString(text);
				}
				TASK_RUNLEVEL_TYPE level;
				if (SUCCEEDED(principal->get_RunLevel(&level)) && level == TASK_RUNLEVEL_HIGHEST && !e.RunAs.empty())
					e.RunAs += L" (highest)";
			}
			wil::com_ptr_nothrow<IActionCollection> actions;
			LONG count = 0;
			if (SUCCEEDED(definition->get_Actions(&actions)) && SUCCEEDED(actions->get_Count(&count))) {
				for (LONG i = 1; i <= count; i++) {
					wil::com_ptr_nothrow<IAction> action;
					if (FAILED(actions->get_Item(i, &action)))
						continue;
					TASK_ACTION_TYPE type;
					if (FAILED(action->get_Type(&type)))
						continue;
					std::wstring command, image;
					if (type == TASK_ACTION_EXEC) {
						wil::com_ptr_nothrow<IExecAction> exec;
						if (SUCCEEDED(action->QueryInterface(IID_PPV_ARGS(&exec)))) {
							std::wstring path, args;
							if (SUCCEEDED(exec->get_Path(&text))) {
								path = Bstr(text);
								::SysFreeString(text);
							}
							if (SUCCEEDED(exec->get_Arguments(&text))) {
								args = Bstr(text);
								::SysFreeString(text);
							}
							command = args.empty() ? path : path + L" " + args;
							auto quoted = path.find(L' ') != std::wstring::npos && path[0] != L'"' ? L"\"" + path + L"\"" : path;
							image = Autoruns::ResolveImage(args.empty() ? quoted : quoted + L" " + args);
						}
					}
					else if (type == TASK_ACTION_COM_HANDLER) {
						wil::com_ptr_nothrow<IComHandlerAction> handler;
						if (SUCCEEDED(action->QueryInterface(IID_PPV_ARGS(&handler))) && SUCCEEDED(handler->get_ClassId(&text))) {
							auto clsid = Bstr(text);
							::SysFreeString(text);
							command = L"COM handler " + clsid;
							image = ComServer(clsid);
						}
					}
					else
						command = type == TASK_ACTION_SEND_EMAIL ? L"Send an e-mail" : L"Show a message";
					if (!command.empty())
						e.Command += (e.Command.empty() ? L"" : L"; ") + command;
					if (e.ImagePath.empty())
						e.ImagePath = image;
				}
			}
			wil::com_ptr_nothrow<ITriggerCollection> triggers;
			if (SUCCEEDED(definition->get_Triggers(&triggers)) && SUCCEEDED(triggers->get_Count(&count))) {
				// each kind once, with how many there are
				std::vector<std::pair<PCWSTR, int>> kinds;
				for (LONG i = 1; i <= count; i++) {
					wil::com_ptr_nothrow<ITrigger> trigger;
					TASK_TRIGGER_TYPE2 type;
					if (FAILED(triggers->get_Item(i, &trigger)) || FAILED(trigger->get_Type(&type)))
						continue;
					auto name = TriggerName(type);
					auto it = std::find_if(kinds.begin(), kinds.end(), [&](auto& k) { return wcscmp(k.first, name) == 0; });
					if (it == kinds.end())
						kinds.push_back({ name, 1 });
					else
						it->second++;
				}
				for (auto& [name, n] : kinds) {
					if (!e.Triggers.empty())
						e.Triggers += L", ";
					e.Triggers += name;
					if (n > 1)
						e.Triggers += L" (" + std::to_wstring(n) + L")";
				}
			}
		}
		entries.push_back(std::move(e));
	}

	void AddTaskFolder(ITaskFolder* folder, std::vector<AutorunEntry>& entries, int depth) {
		BSTR text = nullptr;
		std::wstring path;
		if (SUCCEEDED(folder->get_Path(&text))) {
			path = Bstr(text);
			::SysFreeString(text);
		}
		wil::com_ptr_nothrow<IRegisteredTaskCollection> tasks;
		LONG count = 0;
		if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && SUCCEEDED(tasks->get_Count(&count)))
			for (LONG i = 1; i <= count; i++) {
				wil::com_ptr_nothrow<IRegisteredTask> task;
				VARIANT index{};
				index.vt = VT_I4;
				index.lVal = i;
				if (SUCCEEDED(tasks->get_Item(index, &task)))
					ReadTask(task.get(), path, entries);
			}
		if (depth > 32)
			return;
		wil::com_ptr_nothrow<ITaskFolderCollection> folders;
		if (SUCCEEDED(folder->GetFolders(0, &folders)) && SUCCEEDED(folders->get_Count(&count)))
			for (LONG i = 1; i <= count; i++) {
				wil::com_ptr_nothrow<ITaskFolder> sub;
				VARIANT index{};
				index.vt = VT_I4;
				index.lVal = i;
				if (SUCCEEDED(folders->get_Item(index, &sub)))
					AddTaskFolder(sub.get(), entries, depth + 1);
			}
	}

	HRESULT OpenScheduler(wil::com_ptr_nothrow<ITaskService>& service, wil::com_ptr_nothrow<ITaskFolder>& root) {
		auto hr = ::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&service));
		if (FAILED(hr))
			return hr;
		VARIANT empty{};
		if (FAILED(hr = service->Connect(empty, empty, empty, empty)))
			return hr;
		wil::unique_bstr path(::SysAllocString(L"\\"));
		return service->GetFolder(path.get(), &root);
	}

	void AddTasks(std::vector<AutorunEntry>& entries) {
		wil::com_ptr_nothrow<ITaskService> service;
		wil::com_ptr_nothrow<ITaskFolder> root;
		if (SUCCEEDED(OpenScheduler(service, root)))
			AddTaskFolder(root.get(), entries, 0);
	}

	bool SetError(DWORD error) {
		::SetLastError(error);
		return error == ERROR_SUCCESS;
	}

	bool SetHResult(HRESULT hr) {
		return SetError(SUCCEEDED(hr) ? ERROR_SUCCESS : HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : (DWORD)hr);
	}

	PCWSTR ApprovedName(AutorunEntry const& entry) {
		return entry.Store == AutorunStore::StartupFile ? L"StartupFolder" : entry.Wow64 ? L"Run32" : L"Run";
	}
}

std::wstring Autoruns::ResolveImage(std::wstring const& command) {
	auto text = Trim(Expand(command));
	// Userinit's list ends with a comma
	while (!text.empty() && text.back() == L',')
		text.pop_back();
	if (text.empty())
		return {};
	size_t rest = 0;
	auto image = FirstPath(text, rest, L".exe");
	// rundll32 runs a DLL's function: the DLL is what runs
	auto name = FileName(image);
	if (_wcsicmp(name.c_str(), L"rundll32.exe") == 0 || _wcsicmp(name.c_str(), L"rundll32") == 0) {
		auto args = Trim(text.substr(rest));
		// its own switches ("/d") come before the DLL
		while (!args.empty() && (args[0] == L'/' || args[0] == L'-')) {
			auto space = args.find(L' ');
			args = space == std::wstring::npos ? L"" : Trim(args.substr(space));
		}
		if (!args.empty()) {
			auto comma = args[0] == L'"' ? args.find(L',', args.find(L'"', 1)) : args.find(L',');
			auto dll = Trim(args.substr(0, comma));
			size_t ignored = 0;
			if (auto path = FirstPath(dll, ignored, L".dll"); !path.empty())
				return path;
		}
	}
	return image;
}

std::vector<PackageStartupTask> Autoruns::ParseStartupTasks(std::string_view manifest) {
	std::vector<PackageStartupTask> tasks;
	wil::com_ptr_nothrow<IStream> stream;
	stream.attach(::SHCreateMemStream((BYTE const*)manifest.data(), (UINT)manifest.size()));
	wil::com_ptr_nothrow<IXmlReader> reader;
	if (!stream || FAILED(::CreateXmlReader(IID_PPV_ARGS(&reader), nullptr)))
		return tasks;
	reader->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit);
	if (FAILED(reader->SetInput(stream.get())))
		return tasks;

	auto attribute = [&](PCWSTR name) {
		std::wstring text;
		PCWSTR value = nullptr;
		if (reader->MoveToAttributeByName(name, nullptr) == S_OK && SUCCEEDED(reader->GetValue(&value, nullptr)) && value)
			text = value;
		reader->MoveToElement();
		return text;
	};

	// a StartupTask is in an Extension (desktop:, uap5:), in an Application: its executable is the extension's, else the
	// application's (a UWP app's task)
	std::wstring appExecutable, extensionExecutable;
	XmlNodeType type;
	while (reader->Read(&type) == S_OK) {
		if (type != XmlNodeType_Element)
			continue;
		PCWSTR name = nullptr;
		if (FAILED(reader->GetLocalName(&name, nullptr)) || !name)
			continue;
		if (wcscmp(name, L"Application") == 0) {
			appExecutable = attribute(L"Executable");
			extensionExecutable.clear();
		}
		else if (wcscmp(name, L"Extension") == 0)
			extensionExecutable = attribute(L"Executable");
		else if (wcscmp(name, L"StartupTask") == 0) {
			PackageStartupTask task;
			task.TaskId = attribute(L"TaskId");
			if (task.TaskId.empty())
				continue;
			task.DisplayName = attribute(L"DisplayName");
			auto enabled = attribute(L"Enabled");
			task.Enabled = _wcsicmp(enabled.c_str(), L"true") == 0 || enabled == L"1";
			task.Executable = !extensionExecutable.empty() ? extensionExecutable : appExecutable;
			for (auto& c : task.Executable)
				if (c == L'/')
					c = L'\\';
			tasks.push_back(std::move(task));
		}
	}
	return tasks;
}

std::vector<AutorunEntry> Autoruns::Enum() {
	std::vector<AutorunEntry> entries;
	entries.reserve(1024);
	AddRunKeys(entries);
	AddStartupFolders(entries);
	AddActiveSetup(entries);
	AddPackageTasks(entries);
	AddTasks(entries);
	AddServices(entries);
	AddWinlogon(entries);
	AddAppInit(entries);
	AddBootExecute(entries);
	AddLsa(entries);
	AddHijacks(entries);
	for (auto& e : entries)
		e.ImageFound = !e.ImagePath.empty() && IsFile(e.ImagePath);
	return entries;
}

bool Autoruns::SetEnabled(AutorunEntry const& entry, bool enable) {
	switch (entry.Store) {
		case AutorunStore::RegistryValue:
		case AutorunStore::StartupFile:
		{
			if (!entry.Enabled)
				return SetError(ERROR_NOT_SUPPORTED);
			HKEY key = nullptr;
			auto error = ::RegCreateKeyExW((HKEY)entry.Root, (std::wstring(ApprovedKey) + ApprovedName(entry)).c_str(), 0, nullptr, 0,
				KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, nullptr);
			if (error != ERROR_SUCCESS)
				return SetError(error);
			wil::unique_hkey hold(key);
			// as Task Manager writes it: 2 enabled; 3 disabled, with the time it was disabled
			BYTE data[12]{};
			data[0] = enable ? 2 : 3;
			if (!enable) {
				FILETIME now;
				::GetSystemTimeAsFileTime(&now);
				memcpy(data + 4, &now, sizeof(now));
			}
			return SetError(::RegSetValueExW(key, entry.ValueName.c_str(), 0, REG_BINARY, data, sizeof(data)));
		}
		case AutorunStore::Task:
		{
			wil::com_ptr_nothrow<ITaskService> service;
			wil::com_ptr_nothrow<ITaskFolder> root;
			auto hr = OpenScheduler(service, root);
			if (FAILED(hr))
				return SetHResult(hr);
			wil::com_ptr_nothrow<IRegisteredTask> task;
			wil::unique_bstr path(::SysAllocString(entry.TaskPath.c_str()));
			if (FAILED(hr = root->GetTask(path.get(), &task)))
				return SetHResult(hr);
			return SetHResult(task->put_Enabled(enable ? VARIANT_TRUE : VARIANT_FALSE));
		}
		case AutorunStore::PackageTask:
		{
			HKEY key = nullptr;
			auto error = ::RegCreateKeyExW(HKEY_CURRENT_USER, entry.SubKey.c_str(), 0, nullptr, 0,
				KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, nullptr);
			if (error != ERROR_SUCCESS)
				return SetError(error);
			wil::unique_hkey hold(key);
			if (auto state = ReadDword(key, L"State"); state && (*state == TaskDisabledByPolicy || *state == TaskEnabledByPolicy))
				return SetError(ERROR_ACCESS_DISABLED_BY_POLICY);
			// as Task Manager writes it: enabled, or disabled by the user with when (seconds since 1970)
			DWORD state = enable ? TaskEnabled : TaskDisabledByUser;
			if (error = ::RegSetValueExW(key, L"State", 0, REG_DWORD, (BYTE const*)&state, sizeof(state)); error != ERROR_SUCCESS)
				return SetError(error);
			DWORD value = enable ? 1 : (DWORD)::_time64(nullptr);
			::RegSetValueExW(key, enable ? L"UserEnabledStartupOnce" : L"LastDisabledTime", 0, REG_DWORD, (BYTE const*)&value, sizeof(value));
			return SetError(ERROR_SUCCESS);
		}
	}
	return SetError(ERROR_NOT_SUPPORTED);
}

bool Autoruns::Delete(AutorunEntry const& entry) {
	if (!entry.Deletable)
		return SetError(ERROR_NOT_SUPPORTED);
	bool ok = false;
	switch (entry.Store) {
		case AutorunStore::RegistryValue:
		{
			auto key = OpenKey((HKEY)entry.Root, entry.SubKey, KEY_SET_VALUE);
			if (!key)
				return SetError(ERROR_ACCESS_DENIED);
			ok = SetError(::RegDeleteValueW(key.get(), entry.ValueName.c_str()));
			break;
		}
		case AutorunStore::StartupFile:
			ok = ::DeleteFileW((entry.Location + L"\\" + entry.Name).c_str()) != FALSE;
			break;
		case AutorunStore::Task:
		{
			wil::com_ptr_nothrow<ITaskService> service;
			wil::com_ptr_nothrow<ITaskFolder> root;
			auto hr = OpenScheduler(service, root);
			if (SUCCEEDED(hr)) {
				wil::unique_bstr path(::SysAllocString(entry.TaskPath.c_str()));
				hr = root->DeleteTask(path.get(), 0);
			}
			return SetHResult(hr);
		}
		default:
			return SetError(ERROR_NOT_SUPPORTED);
	}
	// its Startup apps state goes with it (best effort)
	if (ok && entry.Enabled) {
		auto error = ::GetLastError();
		if (auto key = OpenKey((HKEY)entry.Root, std::wstring(ApprovedKey) + ApprovedName(entry), KEY_SET_VALUE))
			::RegDeleteValueW(key.get(), entry.ValueName.c_str());
		::SetLastError(error);
	}
	return ok;
}

PCWSTR Autoruns::RootName(void* root) {
	if (root == HKEY_LOCAL_MACHINE)
		return L"HKLM";
	if (root == HKEY_CURRENT_USER)
		return L"HKCU";
	if (root == HKEY_CLASSES_ROOT)
		return L"HKCR";
	if (root == HKEY_USERS)
		return L"HKU";
	return L"";
}

PCWSTR Autoruns::CategoryName(AutorunCategory category) {
	switch (category) {
		case AutorunCategory::Logon: return L"Logon";
		case AutorunCategory::ScheduledTask: return L"Scheduled Task";
		case AutorunCategory::Service: return L"Service";
		case AutorunCategory::Driver: return L"Driver";
		case AutorunCategory::Winlogon: return L"Winlogon";
		case AutorunCategory::AppInit: return L"AppInit";
		case AutorunCategory::BootExecute: return L"Boot Execute";
		case AutorunCategory::Lsa: return L"LSA Provider";
		case AutorunCategory::ImageHijack: return L"Image Hijack";
	}
	return L"";
}

PCWSTR Autoruns::TaskStateName(AutorunTaskState state) {
	switch (state) {
		case AutorunTaskState::Disabled: return L"Disabled";
		case AutorunTaskState::Queued: return L"Queued";
		case AutorunTaskState::Ready: return L"Ready";
		case AutorunTaskState::Running: return L"Running";
	}
	return L"";
}
