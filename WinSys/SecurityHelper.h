#pragma once

#ifdef WINSYS_NAMESPACE
namespace WinSys {
#endif
	struct SecurityHelper abstract final {
		[[nodiscard]] static bool IsRunningElevated();
		static bool RunElevated(PCWSTR param = nullptr, bool ui = true);
		static bool EnablePrivilege(PCWSTR privName, bool enable);
		[[nodiscard]] static std::wstring GetSidFromUser(PCWSTR name);
	};

#ifdef WINSYS_NAMESPACE
}
#endif
