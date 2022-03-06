#pragma once

namespace WinSys {
	struct SecurityHelper abstract final {
		[[nodiscard]] static bool IsRunningElevated();
		static bool RunElevated(PCWSTR param = nullptr, bool ui = true);
		static bool EnablePrivilege(PCWSTR privName, bool enable);
		[[nodiscard]] static std::wstring GetSidFromUser(PCWSTR name);
	};
}
