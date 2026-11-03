#include "pch.h"
#include "Com.h"
#include <comadmin.h>
#include <Shlwapi.h>
#include <wil/resource.h>
#include <wil/com.h>
#include <algorithm>
#include <cwctype>

#pragma comment(lib, "shlwapi")

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

	ComServerInfo ComServers::Identify(std::wstring_view commandLine, std::wstring_view imagePath, bool wow64) {
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
					if (classes.empty())
						break;
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
