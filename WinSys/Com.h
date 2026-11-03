#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

//
// What a COM server process serves, from its command line and the registry:
// - a surrogate (dllhost.exe /Processid:{AppID}): the app ID's name, else a packaged surrogate's (HKCR\PackagedCom:
//   its server's DisplayName, with the class's DLL), else the classes whose AppID it is (a class's name and DLL), else
//   the class of that ID, else a COM+ application's (the COM+ catalog, through COMAdmin);
// - a local server (-Embedding, /Embedding, /Automation, explorer's /factory,{CLSID}): the classes whose
//   LocalServer32 is the process's image (the app ID's name they share, else the class's if there's one; which of
//   several started it can't be told); a packaged one (-RegisterProcessAsComServer: its classes in no LocalServer32),
//   the server of the process's package (packageFullName) whose Executable is its image, named by its DisplayName or
//   its application's;
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

	// where a registered class runs
	enum class ComServerType : uint8_t {
		Other,			// none of these (a TreatAs, an AppID only...)
		InProc,			// InprocServer32: in the creator
		Handler,		// InprocHandler32 only
		LocalServer,	// LocalServer32 (or a packaged server's executable)
		Surrogate,		// InprocServer32 with an AppID that has DllSurrogate: in dllhost.exe
		Service,		// an AppID with LocalService: in a service
	};

	// a class in HKCR\CLSID (the machine's and the user's) or a packaged one (HKCR\PackagedCom)
	struct ComClassRegistration {
		std::wstring Clsid;			// {...}
		std::wstring Name, ProgId, ThreadingModel;
		ComServerType Type{ ComServerType::Other };
		std::wstring Server;		// as registered: the DLL, the command line (LocalServer32), a packaged class's DLL or executable
		std::wstring ServerFile;	// the file it names, environment variables expanded; empty if none (a service's)
		bool ServerMissing{ false };// ServerFile is a full path that doesn't exist (in the view's System32)
		std::wstring AppId, AppIdName, ServiceName, RunAs;
		bool HasLaunchPermission{ false }, HasAccessPermission{ false };	// the AppID's own (else the machine's defaults)
		std::wstring Package;		// a packaged class's package full name
		bool Wow64{ false };		// the 32-bit view's
		bool PerUser{ false };		// in HKCU\Software\Classes
		bool OverridesMachine{ false };	// per user, and HKLM has the class too: the user's is the one used
	};

	struct ComRegistry final {
		// every registered class of the view, the user's over the machine's (marked), then (the 64-bit view) the
		// packaged ones. Reads the registry: about 8,000 classes, a second or two
		[[nodiscard]] static std::vector<ComClassRegistration> EnumClasses(bool wow64);
		// "In-process", "Local server", "Surrogate (dllhost)"...
		[[nodiscard]] static PCWSTR TypeText(ComServerType type);
		// an AppID's LaunchPermission or AccessPermission (a self-relative security descriptor), else the machine's
		// default (HKLM\Software\Microsoft\Ole DefaultLaunchPermission, DefaultAccessPermission: isDefault); empty if
		// neither is set (COM's built-in default applies)
		[[nodiscard]] static std::vector<uint8_t> GetPermission(std::wstring const& appId, bool launch, bool wow64, bool& isDefault);
	};

	struct ComServers final {
		// what the process serves; Kind None if its command line isn't a COM server's. packageFullName: a packaged
		// process's package (its packaged servers are found only through it). wow64: a 32-bit process (the
		// registry's 32-bit view). Reads the registry, the index the first time and COM+'s catalog for a surrogate
		// found nowhere else (the caller initializes COM). Safe on any thread; callers cache per process
		[[nodiscard]] static ComServerInfo Identify(std::wstring_view commandLine, std::wstring_view imagePath, bool wow64,
			std::wstring_view packageFullName = {});
		// the command line alone: the kind and the ID it names (the surrogate's AppID, a factory's CLSID, the server's name)
		[[nodiscard]] static ComServerKind ParseCommandLine(std::wstring_view commandLine, std::wstring& id);
		// the executable in a LocalServer32 value: quoted or up to ".exe", environment variables expanded
		[[nodiscard]] static std::wstring ServerPath(std::wstring_view value);
		// the classes' index's size (the 64-bit view's), built if it isn't yet; for tests
		[[nodiscard]] static size_t GetIndexedClasses();
	};
}
