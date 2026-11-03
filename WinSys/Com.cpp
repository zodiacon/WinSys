#include "pch.h"
#include "Com.h"
#include <comadmin.h>
#include <Shlwapi.h>
#include <wil/resource.h>
#include <wil/com.h>
#include <algorithm>
#include <cwctype>
#include <appmodel.h>
#include <authz.h>
#include <aclapi.h>

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "authz")

namespace WinSys {
	namespace {
		// a class in HKCR\CLSID that a server process may serve: one with an AppID or a LocalServer32
		struct ClassEntry {
			std::wstring Clsid, Name;
			std::wstring AppId;			// upper case, with braces
			std::wstring InprocServer;	// its DLL (a surrogate's)
		};

		struct ClassIndex {
			bool Built{ false };
			uint64_t Tick{ 0 };
			std::vector<ClassEntry> Classes;
			std::unordered_map<std::wstring, std::vector<uint32_t>> ByAppId;		// upper-case AppID to classes
			std::unordered_map<std::wstring, std::vector<uint32_t>> ByLocalServer;	// lower-case executable path to classes
		};

		// a lookup that misses rebuilds an index this old (a server registered since)
		const uint64_t IndexRefresh = 5 * 60 * 1000;

		wil::srwlock s_Lock;
		ClassIndex s_Index[2];	// the 64-bit and the 32-bit views
		bool s_ComPlusLoaded{ false };
		std::unordered_map<std::wstring, std::wstring> s_ComPlus;	// upper-case application ID to its name

		std::wstring Upper(std::wstring_view text) {
			std::wstring result(text);
			for (auto& ch : result)
				ch = (wchar_t)std::towupper(ch);
			return result;
		}

		std::wstring Lower(std::wstring_view text) {
			std::wstring result(text);
			for (auto& ch : result)
				ch = (wchar_t)std::towlower(ch);
			return result;
		}

		// the 64- or 32-bit view, as RegGetValue's flag
		DWORD ViewFlag(bool wow64) {
			return wow64 ? RRF_SUBKEY_WOW6432KEY : RRF_SUBKEY_WOW6464KEY;
		}

		// a string value (REG_EXPAND_SZ expanded); empty if there's none
		std::wstring ReadString(HKEY key, PCWSTR subKey, PCWSTR value, DWORD flags = 0) {
			DWORD size = 0;
			flags |= RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
			if (::RegGetValue(key, subKey, value, flags, nullptr, nullptr, &size) != ERROR_SUCCESS || size < sizeof(wchar_t))
				return L"";
			std::wstring text(size / sizeof(wchar_t), L'\0');
			if (::RegGetValue(key, subKey, value, flags, nullptr, text.data(), &size) != ERROR_SUCCESS)
				return L"";
			text.resize(wcsnlen(text.c_str(), text.size()));
			// some names end with a line break (VirtualBox's)
			while (!text.empty() && std::iswspace(text.back()))
				text.pop_back();
			return text;
		}

		DWORD ReadDword(HKEY key, PCWSTR subKey, PCWSTR value, DWORD fallback) {
			DWORD data, size = sizeof(data);
			return ::RegGetValue(key, subKey, value, RRF_RT_REG_DWORD, nullptr, &data, &size) == ERROR_SUCCESS ? data : fallback;
		}

		wil::unique_hkey OpenKey(HKEY root, std::wstring const& path, bool wow64) {
			HKEY key;
			if (::RegOpenKeyEx(root, path.c_str(), 0, KEY_READ | (wow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &key) != ERROR_SUCCESS)
				return {};
			return wil::unique_hkey(key);
		}

		// the key's subkeys' names
		std::vector<std::wstring> SubKeys(HKEY key) {
			std::vector<std::wstring> names;
			WCHAR name[256];
			for (DWORD i = 0; ; i++) {
				DWORD length = _countof(name);
				auto error = ::RegEnumKeyEx(key, i, name, &length, nullptr, nullptr, nullptr, nullptr);
				if (error == ERROR_MORE_DATA)
					continue;
				if (error != ERROR_SUCCESS)
					break;
				names.emplace_back(name, length);
			}
			return names;
		}

		void BuildIndex(ClassIndex& index, bool wow64) {
			index = ClassIndex{};
			index.Built = true;
			index.Tick = ::GetTickCount64();
			auto clsid = OpenKey(HKEY_CLASSES_ROOT, L"CLSID", wow64);
			if (!clsid)
				return;
			WCHAR name[128];
			for (DWORD i = 0; ; i++) {
				DWORD length = _countof(name);
				auto error = ::RegEnumKeyEx(clsid.get(), i, name, &length, nullptr, nullptr, nullptr, nullptr);
				if (error == ERROR_MORE_DATA)
					continue;
				if (error != ERROR_SUCCESS)
					break;
				HKEY key;
				if (::RegOpenKeyEx(clsid.get(), name, 0, KEY_READ, &key) != ERROR_SUCCESS)
					continue;
				wil::unique_hkey hold(key);
				auto appId = ReadString(key, nullptr, L"AppID");
				auto local = ReadString(key, L"LocalServer32", nullptr);
				if (appId.empty() && local.empty())
					continue;
				ClassEntry entry;
				entry.Clsid = name;
				entry.Name = ReadString(key, nullptr, nullptr);
				entry.AppId = Upper(appId);
				if (!appId.empty())
					entry.InprocServer = ReadString(key, L"InprocServer32", nullptr);
				auto at = (uint32_t)index.Classes.size();
				if (!entry.AppId.empty())
					index.ByAppId[entry.AppId].push_back(at);
				if (auto path = ComServers::ServerPath(local); !path.empty())
					index.ByLocalServer[Lower(path)].push_back(at);
				index.Classes.push_back(std::move(entry));
			}
		}

		// the view's index, built if it isn't (or rebuilt after a miss once it's old); under the exclusive lock
		ClassIndex& GetIndex(bool wow64, bool missed) {
			auto& index = s_Index[wow64 ? 1 : 0];
			if (!index.Built || (missed && ::GetTickCount64() - index.Tick > IndexRefresh))
				BuildIndex(index, wow64);
			return index;
		}

		// the classes the index has under a key, looked up again in a rebuilt index if none are there
		template<typename Map>
		std::vector<ClassEntry> FindClasses(bool wow64, Map ClassIndex::* map, std::wstring const& key) {
			auto lock = s_Lock.lock_exclusive();
			for (bool missed : { false, true }) {
				auto& index = GetIndex(wow64, missed);
				if (auto it = (index.*map).find(key); it != (index.*map).end()) {
					std::vector<ClassEntry> classes;
					for (auto i : it->second)
						classes.push_back(index.Classes[i]);
					return classes;
				}
			}
			return {};
		}

		// "@{package?ms-resource://...}" and "@dll,-id" names
		std::wstring ResolveIndirect(std::wstring const& text) {
			if (text.empty() || text[0] != L'@')
				return text;
			WCHAR resolved[512];
			return SUCCEEDED(::SHLoadIndirectString(text.c_str(), resolved, _countof(resolved), nullptr)) ? resolved : L"";
		}

		// a packaged surrogate: HKCR\PackagedCom\ClassIndex\{id}\<package>, the package's server whose SurrogateAppId it
		// is and its classes
		bool FindPackaged(ComServerInfo& info, bool wow64) {
			auto index = OpenKey(HKEY_CLASSES_ROOT, L"PackagedCom\\ClassIndex\\" + info.Id, wow64);
			if (!index)
				return false;
			auto packages = SubKeys(index.get());
			if (packages.empty())
				return false;
			info.Package = packages[0];
			info.Registration = ComRegistration::Packaged;
			auto base = L"PackagedCom\\Package\\" + info.Package;
			// its server: the one that names it, else the class's
			DWORD server = ReadDword(HKEY_CLASSES_ROOT, (base + L"\\Class\\" + info.Id).c_str(), L"ServerId", 0);
			if (auto servers = OpenKey(HKEY_CLASSES_ROOT, base + L"\\Server", wow64)) {
				for (auto& name : SubKeys(servers.get()))
					if (Upper(ReadString(servers.get(), name.c_str(), L"SurrogateAppId")) == info.Id) {
						server = (DWORD)_wtoi(name.c_str());
						break;
					}
				info.Name = ResolveIndirect(ReadString(servers.get(), std::to_wstring(server).c_str(), L"DisplayName"));
			}
			if (auto classes = OpenKey(HKEY_CLASSES_ROOT, base + L"\\Class", wow64)) {
				for (auto& name : SubKeys(classes.get())) {
					if (ReadDword(classes.get(), name.c_str(), L"ServerId", 0) != server)
						continue;
					info.Classes++;
					auto dll = ReadString(classes.get(), name.c_str(), L"DllPath");
					if (!dll.empty() && (info.ServerDll.empty() || Upper(name) == info.Id))
						info.ServerDll = dll;
				}
			}
			if (info.Name.empty())
				info.Name = info.Package.substr(0, info.Package.find(L'_'));
			return true;
		}

		// a packaged local server (-RegisterProcessAsComServer and the like): the process's package's server
		// (HKCR\PackagedCom\Package\<package>\Server\<n>) whose Executable, relative to the package, ends its image path
		bool FindPackagedServer(ComServerInfo& info, std::wstring const& package, std::wstring_view imagePath, bool wow64) {
			auto base = L"PackagedCom\\Package\\" + package;
			auto servers = OpenKey(HKEY_CLASSES_ROOT, base + L"\\Server", wow64);
			if (!servers)
				return false;
			auto image = Lower(imagePath);
			for (auto& name : SubKeys(servers.get())) {
				auto executable = Lower(ReadString(servers.get(), name.c_str(), L"Executable"));
				if (executable.empty() || image.size() <= executable.size() || !image.ends_with(executable)
					|| image[image.size() - executable.size() - 1] != L'\\')
					continue;
				info.Registration = ComRegistration::Packaged;
				info.Package = package;
				info.Name = ResolveIndirect(ReadString(servers.get(), name.c_str(), L"DisplayName"));
				if (info.Name.empty())
					info.Name = ResolveIndirect(ReadString(servers.get(), name.c_str(), L"ApplicationDisplayName"));
				if (info.Name.empty())
					info.Name = package.substr(0, package.find(L'_'));
				auto server = (DWORD)_wtoi(name.c_str());
				if (auto classes = OpenKey(HKEY_CLASSES_ROOT, base + L"\\Class", wow64))
					for (auto& clsid : SubKeys(classes.get()))
						if (ReadDword(classes.get(), clsid.c_str(), L"ServerId", 0) == server)
							info.Classes++;
				return true;
			}
			return false;
		}

		std::wstring VariantText(VARIANT& v) {
			std::wstring text;
			if (v.vt == VT_BSTR && v.bstrVal)
				text = v.bstrVal;
			::VariantClear(&v);
			return text;
		}

		// the COM+ applications, read once from the catalog; under the exclusive lock
		void LoadComPlus() {
			if (s_ComPlusLoaded)
				return;
			s_ComPlusLoaded = true;
			wil::com_ptr_nothrow<ICOMAdminCatalog> catalog;
			if (FAILED(::CoCreateInstance(__uuidof(COMAdminCatalog), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&catalog))))
				return;
			wil::com_ptr_nothrow<IDispatch> dispatch;
			wil::unique_bstr name(::SysAllocString(L"Applications"));
			if (!name || FAILED(catalog->GetCollection(name.get(), &dispatch)))
				return;
			auto collection = dispatch.try_query<ICatalogCollection>();
			if (!collection || FAILED(collection->Populate()))
				return;
			long count = 0;
			collection->get_Count(&count);
			for (long i = 0; i < count; i++) {
				wil::com_ptr_nothrow<IDispatch> item;
				if (FAILED(collection->get_Item(i, &item)))
					continue;
				auto object = item.try_query<ICatalogObject>();
				if (!object)
					continue;
				VARIANT key, value;
				::VariantInit(&key);
				::VariantInit(&value);
				object->get_Key(&key);
				object->get_Name(&value);
				auto id = Upper(VariantText(key));
				if (!id.empty())
					s_ComPlus[id] = VariantText(value);
				else
					::VariantClear(&value);
			}
		}

		// "/processid:" and the like: the text after the switch, from the lower-case copy's position
		size_t FindSwitch(std::wstring const& lower, std::wstring_view name) {
			for (size_t at = lower.find(name); at != std::wstring::npos; at = lower.find(name, at + 1)) {
				// a switch starts with '-' or '/' after a space (or the start)
				if (at > 0 && (lower[at - 1] == L'-' || lower[at - 1] == L'/') && (at == 1 || lower[at - 2] == L' ' || lower[at - 2] == L'"'))
					return at + name.size();
			}
			return std::wstring::npos;
		}

		bool HasSwitch(std::wstring const& lower, std::wstring_view name) {
			auto end = FindSwitch(lower, name);
			return end != std::wstring::npos && (end == lower.size() || lower[end] == L' ' || lower[end] == L'"');
		}

		// a GUID in braces at the position; empty if there's none
		std::wstring GuidAt(std::wstring_view text, size_t at) {
			if (at >= text.size() || text[at] != L'{')
				return L"";
			auto end = text.find(L'}', at);
			if (end == std::wstring_view::npos || end - at != 37)
				return L"";
			return Upper(text.substr(at, 38));
		}
	}

	std::wstring ComServerInfo::Describe() const {
		switch (Kind) {
			case ComServerKind::Surrogate:
				if (Registration == ComRegistration::ComPlus)
					return L"COM+ Application: " + (Name.empty() ? Id : Name);
				return L"COM Surrogate: " + (Name.empty() ? Id : Name);
			case ComServerKind::LocalServer:
			{
				std::wstring text = Name.empty() ? L"COM Server" : L"COM Server: " + Name;
				if (Classes > 1)
					text += L" (" + std::to_wstring(Classes) + L" classes)";
				return text;
			}
			case ComServerKind::WinRtServer:
				return L"WinRT Server: " + Name;
		}
		return L"";
	}

	ComServerKind ComServers::ParseCommandLine(std::wstring_view commandLine, std::wstring& id) {
		id.clear();
		auto lower = Lower(commandLine);
		if (auto at = FindSwitch(lower, L"processid:"); at != std::wstring::npos) {
			id = GuidAt(commandLine, at);
			if (!id.empty())
				return ComServerKind::Surrogate;
		}
		if (auto at = FindSwitch(lower, L"servername:"); at != std::wstring::npos) {
			auto end = commandLine.find_first_of(L" \"", at);
			id = std::wstring(commandLine.substr(at, end == std::wstring_view::npos ? std::wstring_view::npos : end - at));
			if (!id.empty())
				return ComServerKind::WinRtServer;
		}
		// explorer's: /factory,{CLSID} -Embedding
		if (auto at = FindSwitch(lower, L"factory,"); at != std::wstring::npos) {
			id = GuidAt(commandLine, at);
			if (!id.empty())
				return ComServerKind::LocalServer;
		}
		if (HasSwitch(lower, L"embedding") || HasSwitch(lower, L"automation"))
			return ComServerKind::LocalServer;
		return ComServerKind::None;
	}

	std::wstring ComServers::ServerPath(std::wstring_view value) {
		while (!value.empty() && value.front() == L' ')
			value.remove_prefix(1);
		std::wstring path;
		if (!value.empty() && value.front() == L'"') {
			auto end = value.find(L'"', 1);
			path = value.substr(1, end == std::wstring_view::npos ? std::wstring_view::npos : end - 1);
		}
		else {
			auto lower = Lower(value);
			auto exe = lower.find(L".exe");
			path = exe != std::wstring::npos ? value.substr(0, exe + 4) : value.substr(0, value.find(L' '));
		}
		if (path.find(L'%') != std::wstring::npos) {
			WCHAR expanded[MAX_PATH * 2];
			if (auto length = ::ExpandEnvironmentStrings(path.c_str(), expanded, _countof(expanded)); length > 0 && length <= _countof(expanded))
				path = expanded;
		}
		return path;
	}

	size_t ComServers::GetIndexedClasses() {
		auto lock = s_Lock.lock_exclusive();
		return GetIndex(false, false).Classes.size();
	}

	ComServerInfo ComServers::Identify(std::wstring_view commandLine, std::wstring_view imagePath, bool wow64, std::wstring_view packageFullName) {
		ComServerInfo info;
		info.Kind = ParseCommandLine(commandLine, info.Id);
		auto flag = ViewFlag(wow64);
		switch (info.Kind) {
			case ComServerKind::Surrogate:
			{
				info.Name = ResolveIndirect(ReadString(HKEY_CLASSES_ROOT, (L"AppID\\" + info.Id).c_str(), nullptr, flag));
				if (!info.Name.empty())
					info.Registration = ComRegistration::Classic;
				// the classes it hosts: a name if the app ID has none, and a DLL
				auto classes = FindClasses(wow64, &ClassIndex::ByAppId, info.Id);
				if (!classes.empty()) {
					info.Registration = ComRegistration::Classic;
					info.Classes = (uint32_t)classes.size();
					for (auto& c : classes) {
						if (info.Name.empty() && !c.Name.empty())
							info.Name = c.Name;
						if (info.ServerDll.empty() && !c.InprocServer.empty())
							info.ServerDll = c.InprocServer;
					}
					if (info.Name.empty())
						info.Name = classes[0].Clsid;
				}
				if (info.Registration == ComRegistration::Unknown && FindPackaged(info, wow64))
					break;
				if (info.Registration == ComRegistration::Unknown) {
					// a class of that ID
					auto key = L"CLSID\\" + info.Id;
					info.Name = ReadString(HKEY_CLASSES_ROOT, key.c_str(), nullptr, flag);
					info.ServerDll = ReadString(HKEY_CLASSES_ROOT, (key + L"\\InprocServer32").c_str(), nullptr, flag);
					if (!info.Name.empty() || !info.ServerDll.empty()) {
						info.Registration = ComRegistration::Classic;
						info.Classes = 1;
					}
				}
				if (info.Registration == ComRegistration::Unknown) {
					auto lock = s_Lock.lock_exclusive();
					LoadComPlus();
					if (auto it = s_ComPlus.find(info.Id); it != s_ComPlus.end()) {
						info.Registration = ComRegistration::ComPlus;
						info.Name = it->second;
					}
				}
				break;
			}

			case ComServerKind::LocalServer:
				if (!info.Id.empty()) {
					// a factory's class
					info.Name = ReadString(HKEY_CLASSES_ROOT, (L"CLSID\\" + info.Id).c_str(), nullptr, flag);
					info.Registration = info.Name.empty() ? ComRegistration::Unknown : ComRegistration::Classic;
					info.Classes = 1;
					break;
				}
				else {
					auto classes = FindClasses(wow64, &ClassIndex::ByLocalServer, Lower(imagePath));
					if (classes.empty()) {
						if (!packageFullName.empty())
							FindPackagedServer(info, std::wstring(packageFullName), imagePath, wow64);
						break;
					}
					info.Registration = ComRegistration::Classic;
					info.Classes = (uint32_t)classes.size();
					// the app ID they share names them, else the class if there's one (which of several started the
					// process can't be told: only their count, then)
					auto& appId = classes[0].AppId;
					if (!appId.empty() && std::ranges::all_of(classes, [&](auto& c) { return c.AppId == appId; }))
						info.Name = ResolveIndirect(ReadString(HKEY_CLASSES_ROOT, (L"AppID\\" + appId).c_str(), nullptr, flag));
					if (info.Name.empty() && classes.size() == 1)
						info.Name = classes[0].Name;
				}
				break;

			case ComServerKind::WinRtServer:
				info.Name = info.Id;
				break;
		}
		return info;
	}
}

namespace WinSys {
	namespace {
		struct AppIdInfo {
			std::wstring Name, ServiceName, RunAs;
			bool Surrogate{ false };	// DllSurrogate is there (empty: dllhost.exe)
			bool Launch{ false }, Access{ false };
		};

		bool HasValue(HKEY key, PCWSTR value) {
			return ::RegQueryValueEx(key, value, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
		}

		// the view's app IDs (HKCR\AppID: the machine's and the user's merged), by upper-case ID
		std::unordered_map<std::wstring, AppIdInfo> ReadAppIds(bool wow64) {
			std::unordered_map<std::wstring, AppIdInfo> ids;
			auto root = OpenKey(HKEY_CLASSES_ROOT, L"AppID", wow64);
			if (!root)
				return ids;
			for (auto& name : SubKeys(root.get())) {
				if (name.empty() || name[0] != L'{')
					continue;	// the executables' names (dllhost.exe), which point at an AppID
				HKEY key;
				if (::RegOpenKeyEx(root.get(), name.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
					continue;
				wil::unique_hkey hold(key);
				AppIdInfo info;
				info.Name = ResolveIndirect(ReadString(key, nullptr, nullptr));
				info.ServiceName = ReadString(key, nullptr, L"LocalService");
				info.RunAs = ReadString(key, nullptr, L"RunAs");
				info.Surrogate = HasValue(key, L"DllSurrogate");
				info.Launch = HasValue(key, L"LaunchPermission");
				info.Access = HasValue(key, L"AccessPermission");
				ids[Upper(name)] = std::move(info);
			}
			return ids;
		}

		// a 32-bit class's System32 is SysWOW64 (the file system's redirection, which this 64-bit process doesn't get)
		std::wstring ViewPath(std::wstring const& path, bool wow64) {
			if (!wow64)
				return path;
			WCHAR system[MAX_PATH];
			auto length = ::GetSystemDirectory(system, _countof(system));
			if (length == 0 || path.size() < length || ::_wcsnicmp(path.c_str(), system, length) != 0
				|| (path.size() > length && path[length] != L'\\'))
				return path;
			WCHAR wow[MAX_PATH];
			if (!::GetSystemWow64Directory(wow, _countof(wow)))
				return path;
			return wow + path.substr(length);
		}

		// environment variables expanded as the view's processes have them: a 32-bit process's %ProgramFiles% and
		// %CommonProgramFiles% are the (x86) folders (a 32-bit installer's REG_EXPAND_SZ values use them so)
		std::wstring Expand(std::wstring text, bool wow64) {
			if (text.find(L'%') == std::wstring::npos)
				return text;
			if (wow64) {
				for (auto [name, x86] : { std::pair{ L"%programfiles%", L"%ProgramFiles(x86)%" },
					std::pair{ L"%commonprogramfiles%", L"%CommonProgramFiles(x86)%" } }) {
					auto lower = Lower(text);
					if (auto at = lower.find(name); at != std::wstring::npos)
						text.replace(at, wcslen(name), x86);
				}
			}
			WCHAR expanded[MAX_PATH * 2];
			auto length = ::ExpandEnvironmentStrings(text.c_str(), expanded, _countof(expanded));
			return length > 0 && length <= _countof(expanded) ? expanded : text;
		}

		//
		// Access checks as a standard user would get them (Authz): the current user's SID with Everyone, Authenticated
		// Users, Users and Interactive, and none of its other groups (Administrators) or privileges (Backup, Restore),
		// so an elevated caller sees what a limited one could do. Folders' results are cached.
		//
		class StandardUserCheck {
		public:
			StandardUserCheck() {
				if (!::AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, nullptr, nullptr, nullptr, nullptr, &m_Manager))
					return;
				// the user's SID, from the process token (the same user, elevated or not)
				BYTE buffer[256];
				DWORD size;
				if (!::GetTokenInformation(::GetCurrentProcessToken(), TokenUser, buffer, sizeof(buffer), &size))
					return;
				auto user = reinterpret_cast<TOKEN_USER*>(buffer)->User.Sid;
				AUTHZ_CLIENT_CONTEXT_HANDLE context;
				if (!::AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, user, m_Manager, nullptr, {}, nullptr, &context))
					return;
				WELL_KNOWN_SID_TYPE groups[] = { WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid };
				BYTE sids[_countof(groups)][SECURITY_MAX_SID_SIZE];
				SID_AND_ATTRIBUTES attributes[_countof(groups)];
				for (int i = 0; i < _countof(groups); i++) {
					DWORD length = SECURITY_MAX_SID_SIZE;
					::CreateWellKnownSid(groups[i], nullptr, sids[i], &length);
					attributes[i] = { sids[i], SE_GROUP_ENABLED | SE_GROUP_MANDATORY };
				}
				if (!::AuthzAddSidsToContext(context, attributes, _countof(groups), nullptr, 0, &m_Context))
					m_Context = nullptr;
				::AuthzFreeContext(context);
			}
			~StandardUserCheck() {
				if (m_Context)
					::AuthzFreeContext(m_Context);
				if (m_Manager)
					::AuthzFreeResourceManager(m_Manager);
			}
			StandardUserCheck(StandardUserCheck const&) = delete;
			StandardUserCheck& operator=(StandardUserCheck const&) = delete;

			bool Writable(std::wstring const& path) {
				if (!m_Context || path.size() < 3)
					return false;
				auto attributes = ::GetFileAttributes(path.c_str());
				auto slash = path.find_last_of(L'\\');
				if (slash == std::wstring::npos)
					return false;
				auto folder = path.substr(0, slash);
				if (attributes != INVALID_FILE_ATTRIBUTES) {
					// write it, change its DACL or owner; or delete it (or any of the folder's) and create it again
					auto file = Granted(path);
					if (file & (FILE_WRITE_DATA | WRITE_DAC | WRITE_OWNER))
						return true;
					auto dir = GrantedFolder(folder);
					return (dir & FILE_ADD_FILE) && ((file & DELETE) || (dir & FILE_DELETE_CHILD));
				}
				// missing: create it where it would be, or the folders on the way from the nearest that exists
				bool immediate = true;
				while (::GetFileAttributes(folder.c_str()) == INVALID_FILE_ATTRIBUTES) {
					auto up = folder.find_last_of(L'\\');
					if (up == std::wstring::npos || up < 2)
						return false;
					folder.resize(up);
					immediate = false;
				}
				if (folder.size() == 2)
					folder += L'\\';	// a drive's root
				return (GrantedFolder(folder) & (immediate ? FILE_ADD_FILE : FILE_ADD_SUBDIRECTORY)) != 0;
			}

		private:
			ACCESS_MASK GrantedFolder(std::wstring const& folder) {
				auto key = Lower(folder);
				if (auto it = m_Folders.find(key); it != m_Folders.end())
					return it->second;
				return m_Folders[key] = Granted(folder);
			}

			// what the security descriptor grants the context (MAXIMUM_ALLOWED); none if it can't be read
			ACCESS_MASK Granted(std::wstring const& path) {
				PSECURITY_DESCRIPTOR sd = nullptr;
				if (::GetNamedSecurityInfo(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
					nullptr, nullptr, nullptr, nullptr, &sd) != ERROR_SUCCESS)
					return 0;
				AUTHZ_ACCESS_REQUEST request{ MAXIMUM_ALLOWED };
				ACCESS_MASK granted = 0;
				DWORD error = 0;
				AUTHZ_ACCESS_REPLY reply{ 1, &granted, nullptr, &error };
				if (!::AuthzAccessCheck(0, m_Context, &request, nullptr, sd, nullptr, 0, &reply, nullptr) || error != ERROR_SUCCESS)
					granted = 0;
				::LocalFree(sd);
				return granted;
			}

			AUTHZ_RESOURCE_MANAGER_HANDLE m_Manager{ nullptr };
			AUTHZ_CLIENT_CONTEXT_HANDLE m_Context{ nullptr };
			std::unordered_map<std::wstring, ACCESS_MASK> m_Folders;
		};

		// a DLL's file (quotes taken off); its existence checked only for a full path (a bare name is searched for)
		void SetServerFile(ComClassRegistration& c, std::wstring file) {
			if (file.size() >= 2 && file.front() == L'"') {
				auto end = file.find(L'"', 1);
				file = file.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
			}
			c.ServerFile = Expand(file, c.Wow64);
			bool full = c.ServerFile.size() > 2 && (c.ServerFile[1] == L':' || c.ServerFile.starts_with(L"\\\\"));
			c.ServerMissing = full && ::GetFileAttributes(ViewPath(c.ServerFile, c.Wow64).c_str()) == INVALID_FILE_ATTRIBUTES;
		}

		// the DLL a rundll32 command line runs: after the executable, quoted or up to the comma ("shell32.dll,Entry")
		std::wstring RundllTarget(std::wstring const& commandLine) {
			std::wstring_view rest(commandLine);
			while (!rest.empty() && rest.front() == L' ')
				rest.remove_prefix(1);
			if (!rest.empty() && rest.front() == L'"') {
				auto end = rest.find(L'"', 1);
				rest = end == std::wstring_view::npos ? std::wstring_view() : rest.substr(end + 1);
			}
			else {
				auto exe = Lower(rest).find(L".exe");
				rest = exe == std::wstring::npos ? std::wstring_view() : rest.substr(exe + 4);
			}
			while (!rest.empty() && rest.front() == L' ')
				rest.remove_prefix(1);
			if (!rest.empty() && rest.front() == L'"') {
				auto end = rest.find(L'"', 1);
				return std::wstring(rest.substr(1, end == std::wstring_view::npos ? std::wstring_view::npos : end - 1));
			}
			return std::wstring(rest.substr(0, rest.find_first_of(L", ")));
		}

		// a bare name (found in System32) or a file in the Windows folder
		bool IsSystemDll(std::wstring const& file) {
			if (file.empty())
				return false;
			if (file.find(L'\\') == std::wstring::npos)
				return true;
			WCHAR windows[MAX_PATH];
			auto length = ::GetWindowsDirectory(windows, _countof(windows));
			return length && file.size() > length && ::_wcsnicmp(file.c_str(), windows, length) == 0 && file[length] == L'\\';
		}

		void ReadClass(HKEY key, ComClassRegistration& c, std::unordered_map<std::wstring, AppIdInfo> const& appIds) {
			c.Name = ResolveIndirect(ReadString(key, nullptr, nullptr));
			c.ProgId = ReadString(key, L"ProgID", nullptr);
			// RegGetValue would expand REG_EXPAND_SZ: the values as registered are read without that
			auto inproc = ReadString(key, L"InprocServer32", nullptr, RRF_NOEXPAND);
			auto local = ReadString(key, L"LocalServer32", nullptr, RRF_NOEXPAND);
			auto handler = ReadString(key, L"InprocHandler32", nullptr, RRF_NOEXPAND);
			c.AppId = Upper(ReadString(key, nullptr, L"AppID"));
			AppIdInfo const* app = nullptr;
			if (!c.AppId.empty())
				if (auto it = appIds.find(c.AppId); it != appIds.end())
					app = &it->second;
			if (app) {
				c.AppIdName = app->Name;
				c.ServiceName = app->ServiceName;
				c.RunAs = app->RunAs;
				c.HasLaunchPermission = app->Launch;
				c.HasAccessPermission = app->Access;
			}
			if (!local.empty()) {
				c.Type = ComServerType::LocalServer;
				c.Server = local;
				c.ServerFile = ComServers::ServerPath(Expand(local, c.Wow64));
				// rpcss (64-bit) starts it: its System32 isn't redirected, as a 32-bit DLL's is
				bool full = c.ServerFile.size() > 2 && c.ServerFile[1] == L':';
				c.ServerMissing = full && ::GetFileAttributes(c.ServerFile.c_str()) == INVALID_FILE_ATTRIBUTES;
				c.Interpreter = ComRegistry::InterpreterOf(c.ServerFile);
				if (c.Interpreter == L"rundll32.exe")
					c.InterpreterRunsSystemDll = IsSystemDll(RundllTarget(Expand(local, c.Wow64)));
			}
			else if (app && !app->ServiceName.empty()) {
				c.Type = ComServerType::Service;
				c.Server = app->ServiceName;
			}
			else if (!inproc.empty()) {
				c.Type = app && app->Surrogate ? ComServerType::Surrogate : ComServerType::InProc;
				c.Server = inproc;
				SetServerFile(c, inproc);
			}
			else if (!handler.empty()) {
				c.Type = ComServerType::Handler;
				c.Server = handler;
				SetServerFile(c, handler);
			}
			if (!inproc.empty() || !handler.empty())
				c.ThreadingModel = ReadString(key, inproc.empty() ? L"InprocHandler32" : L"InprocServer32", L"ThreadingModel");
			// a scriptlet: scrobj.dll runs the script its ScriptletURL names (a file, or a URL)
			if (auto slash = c.ServerFile.find_last_of(L'\\'); !inproc.empty()
				&& ::_wcsicmp(c.ServerFile.c_str() + (slash == std::wstring::npos ? 0 : slash + 1), L"scrobj.dll") == 0) {
				// none: the scriptlet engine's own classes (the runtime, its factories)
				c.ScriptletUrl = ReadString(key, L"ScriptletURL", nullptr);
			}
		}

		// a root's CLSID key's classes (HKLM\Software\Classes or HKCU\Software\Classes)
		void ReadClasses(HKEY root, bool wow64, bool perUser, std::unordered_map<std::wstring, AppIdInfo> const& appIds,
			std::vector<ComClassRegistration>& classes, std::unordered_map<std::wstring, size_t>& byClsid) {
			auto clsid = OpenKey(root, L"Software\\Classes\\CLSID", wow64);
			if (!clsid)
				return;
			for (auto& name : SubKeys(clsid.get())) {
				if (name.empty() || name[0] != L'{')
					continue;	// CLSID's own values' keys (none usually)
				HKEY key;
				if (::RegOpenKeyEx(clsid.get(), name.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
					continue;
				wil::unique_hkey hold(key);
				ComClassRegistration c;
				c.Clsid = Upper(name);
				c.Wow64 = wow64;
				c.PerUser = perUser;
				ReadClass(key, c, appIds);
				// the user's hides the machine's in HKCR; both are kept (each hive's registrations shown apart)
				if (auto it = byClsid.find(c.Clsid); perUser && it != byClsid.end()) {
					c.OverridesMachine = true;
					classes[it->second].OverriddenByUser = true;
				}
				else if (!perUser)
					byClsid[c.Clsid] = classes.size();
				classes.push_back(std::move(c));
			}
		}

		// HKCR\PackagedCom\Package\<package>: each class, with its server (a surrogate's or an executable)
		void ReadPackagedClasses(std::vector<ComClassRegistration>& classes) {
			auto packages = OpenKey(HKEY_CLASSES_ROOT, L"PackagedCom\\Package", false);
			if (!packages)
				return;
			for (auto& package : SubKeys(packages.get())) {
				WCHAR path[MAX_PATH * 2];
				UINT32 length = _countof(path);
				std::wstring folder = ::GetPackagePathByFullName(package.c_str(), &length, path) == ERROR_SUCCESS ? path : L"";
				struct Server {
					std::wstring Name, Executable, SurrogateAppId;
				};
				std::unordered_map<DWORD, Server> servers;
				if (auto key = OpenKey(packages.get(), package + L"\\Server", false))
					for (auto& n : SubKeys(key.get())) {
						Server s;
						s.Name = ResolveIndirect(ReadString(key.get(), n.c_str(), L"DisplayName"));
						s.Executable = ReadString(key.get(), n.c_str(), L"Executable");
						s.SurrogateAppId = ReadString(key.get(), n.c_str(), L"SurrogateAppId");
						servers[(DWORD)_wtoi(n.c_str())] = std::move(s);
					}
				auto key = OpenKey(packages.get(), package + L"\\Class", false);
				if (!key)
					continue;
				for (auto& clsid : SubKeys(key.get())) {
					ComClassRegistration c;
					c.Clsid = Upper(clsid);
					c.Package = package;
					auto dll = ReadString(key.get(), clsid.c_str(), L"DllPath");
					auto it = servers.find(ReadDword(key.get(), clsid.c_str(), L"ServerId", 0));
					auto server = it != servers.end() ? &it->second : nullptr;
					if (server) {
						c.Name = server->Name;
						c.AppId = Upper(server->SurrogateAppId);
					}
					std::wstring file;
					if (server && !server->Executable.empty()) {
						c.Type = ComServerType::LocalServer;
						file = server->Executable;
					}
					else if (!dll.empty()) {
						c.Type = server && !server->SurrogateAppId.empty() ? ComServerType::Surrogate : ComServerType::InProc;
						file = dll;
					}
					c.Server = file;
					// relative to the package's folder
					if (!file.empty() && !folder.empty() && !(file.size() > 2 && file[1] == L':'))
						file = folder + L"\\" + file;
					if (!file.empty())
						SetServerFile(c, file);
					if (c.Name.empty())
						c.Name = package.substr(0, package.find(L'_'));
					classes.push_back(std::move(c));
				}
			}
		}
	}

	std::vector<ComClassRegistration> ComRegistry::EnumClasses(bool wow64) {
		auto appIds = ReadAppIds(wow64);
		std::vector<ComClassRegistration> classes;
		std::unordered_map<std::wstring, size_t> byClsid;
		classes.reserve(10000);
		ReadClasses(HKEY_LOCAL_MACHINE, wow64, false, appIds, classes, byClsid);
		ReadClasses(HKEY_CURRENT_USER, wow64, true, appIds, classes, byClsid);
		if (!wow64)
			ReadPackagedClasses(classes);
		// a machine-wide class's server a standard user could replace (a per-user class runs that user's own code
		// anyway; a package's folder is the system's)
		StandardUserCheck check;
		std::unordered_map<std::wstring, bool> files;
		for (auto& c : classes) {
			if (c.PerUser || !c.Package.empty() || c.ServerFile.size() < 3 || c.ServerFile[1] != L':')
				continue;
			auto path = c.Type == ComServerType::LocalServer ? c.ServerFile : ViewPath(c.ServerFile, c.Wow64);
			auto key = Lower(path);
			auto it = files.find(key);
			if (it == files.end())
				it = files.emplace(key, check.Writable(path)).first;
			c.ServerWritable = it->second;
		}
		return classes;
	}

	bool ComRegistry::IsWritableByUsers(std::wstring const& path) {
		StandardUserCheck check;
		return check.Writable(path);
	}

	std::wstring ComRegistry::InterpreterOf(std::wstring const& file) {
		static const PCWSTR interpreters[] = {
			L"rundll32.exe", L"regsvr32.exe", L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"mshta.exe", L"wscript.exe",
			L"cscript.exe", L"msiexec.exe", L"conhost.exe",
		};
		auto slash = file.find_last_of(L"\\/");
		auto name = Lower(slash == std::wstring::npos ? file : file.substr(slash + 1));
		for (auto i : interpreters)
			if (name == i)
				return name;
		return L"";
	}

	PCWSTR ComRegistry::TypeText(ComServerType type) {
		switch (type) {
			case ComServerType::InProc: return L"In-process";
			case ComServerType::Handler: return L"In-process handler";
			case ComServerType::LocalServer: return L"Local server";
			case ComServerType::Surrogate: return L"Surrogate (dllhost)";
			case ComServerType::Service: return L"Service";
		}
		return L"Other";
	}

	std::vector<uint8_t> ComRegistry::GetPermission(std::wstring const& appId, bool launch, bool wow64, bool& isDefault) {
		auto read = [](HKEY root, std::wstring const& path, PCWSTR value, bool wow64) {
			std::vector<uint8_t> data;
			auto key = OpenKey(root, path, wow64);
			DWORD size = 0;
			if (!key || ::RegQueryValueEx(key.get(), value, nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS || size == 0)
				return data;
			data.resize(size);
			if (::RegQueryValueEx(key.get(), value, nullptr, nullptr, data.data(), &size) != ERROR_SUCCESS
				|| !::IsValidSecurityDescriptor(data.data()))
				data.clear();
			return data;
		};
		isDefault = false;
		if (!appId.empty()) {
			auto sd = read(HKEY_CLASSES_ROOT, L"AppID\\" + appId, launch ? L"LaunchPermission" : L"AccessPermission", wow64);
			if (!sd.empty())
				return sd;
		}
		isDefault = true;
		return read(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Ole", launch ? L"DefaultLaunchPermission" : L"DefaultAccessPermission", false);
	}
}
