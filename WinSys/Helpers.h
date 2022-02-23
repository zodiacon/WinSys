#pragma once

#ifdef WINSYS_NAMESPACE
namespace WinSys {
#endif
	struct Helpers final abstract {
		static std::wstring GetDosNameFromNtName(PCWSTR name, bool refresh = false);
		static std::wstring GetErrorText(DWORD error);
	};
#ifdef WINSYS_NAMESPACE
}
#endif

