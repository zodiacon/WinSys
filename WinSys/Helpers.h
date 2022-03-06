#pragma once

#include "Processes.h"

namespace WinSys {
	struct Helpers final abstract {
		static std::wstring GetDosNameFromNtName(PCWSTR name, bool refresh = false);
		static std::wstring GetErrorText(DWORD error);
		static int PriorityClassToPriority(ProcessPriorityClass pc);
	};
}


