#pragma once

#include "Processes.h"

#ifdef WINSYS_NAMESPACE
namespace WinSys {
#endif
	struct Helpers final abstract {
		static std::wstring GetDosNameFromNtName(PCWSTR name, bool refresh = false);
		static std::wstring GetErrorText(DWORD error);
		static int PriorityClassToPriority(PriorityClass pc);
	};
#ifdef WINSYS_NAMESPACE
}
#endif

