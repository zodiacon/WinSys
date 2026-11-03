#pragma once

#include <cstdint>
#include <string>
#include <string_view>

//
// What a COM server process serves, from its command line and the registry:
// - a surrogate (dllhost.exe /Processid:{AppID}): the app ID's name, else a packaged surrogate's (HKCR\PackagedCom:
//   its server's DisplayName, with the class's DLL), else the classes whose AppID it is (a class's name and DLL), else
//   the class of that ID, else a COM+ application's (the COM+ catalog, through COMAdmin);
// - a local server (-Embedding, /Embedding, /Automation, explorer's /factory,{CLSID}): the classes whose
//   LocalServer32 is the process's image (the app ID's name they share, else the class's if there's one; which of
//   several started it can't be told);
// - a Windows Runtime server (-ServerName:<name>): the server's name.
// The classes are read once into an index (those with an AppID or a LocalServer32: about 1,000 of 8,000 here, in
// about 0.4 s; read again after five minutes when a lookup misses), apart for the 32-bit view: callers look up off
// their UI thread.
//

namespace WinSys {
	enum class ComServerKind : uint8_t {
		None,			// not a COM server's command line
		Surrogate,		// dllhost.exe
		LocalServer,	// an executable started for its classes
		WinRtServer,	// a Windows Runtime out-of-process server
	};

	enum class ComRegistration : uint8_t {
		Unknown,	// not found
		Classic,	// HKCR\AppID, HKCR\CLSID
		Packaged,	// HKCR\PackagedCom (an MSIX package's)
		ComPlus,	// the COM+ catalog
	};

	struct ComServerInfo {
		ComServerKind Kind{ ComServerKind::None };
		ComRegistration Registration{ ComRegistration::Unknown };
		std::wstring Id;		// the surrogate's AppID, a factory's CLSID, the Windows Runtime server's name ({...} with braces)
		std::wstring Name;		// the app ID's, the packaged server's, the COM+ application's or a class's; empty if not known
		std::wstring ServerDll;	// a surrogate's class's DLL (a packaged one's relative to its package's folder)
		std::wstring Package;	// packaged COM: the package's full name
		uint32_t Classes{ 0 };	// the registered classes it serves, as far as the registry says

		// "COM Surrogate: Plan9FileSystem", "COM Server: PerAppRuntimeBroker (3 classes)", "COM Server (13 classes)",
		// "COM+ Application: System Application", "WinRT Server: ..."; empty for None
		[[nodiscard]] std::wstring Describe() const;
	};

	struct ComServers final {
		// what the process serves; Kind None if its command line isn't a COM server's. wow64: a 32-bit process (the
		// registry's 32-bit view). Reads the registry, the index the first time and COM+'s catalog for a surrogate
		// found nowhere else (the caller initializes COM). Safe on any thread; callers cache per process
		[[nodiscard]] static ComServerInfo Identify(std::wstring_view commandLine, std::wstring_view imagePath, bool wow64);
		// the command line alone: the kind and the ID it names (the surrogate's AppID, a factory's CLSID, the server's name)
		[[nodiscard]] static ComServerKind ParseCommandLine(std::wstring_view commandLine, std::wstring& id);
		// the executable in a LocalServer32 value: quoted or up to ".exe", environment variables expanded
		[[nodiscard]] static std::wstring ServerPath(std::wstring_view value);
		// the classes' index's size (the 64-bit view's), built if it isn't yet; for tests
		[[nodiscard]] static size_t GetIndexedClasses();
	};
}
