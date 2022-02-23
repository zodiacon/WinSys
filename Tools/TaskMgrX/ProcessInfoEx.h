#pragma once

#include <ProcessInfo.h>

enum class ProcessAttributes : DWORD {
	None =			0,
	InJob =			1 << 1,
	Managed =		1 << 2,
	Wow64 =			1 << 3,
	Protected =		1 << 4,
	Immersive =		1 << 5,
	Secure =		1 << 6,
	Suspended =		1 << 7,
	Service =		1 << 8,
	Pico =			1 << 9,
	Minimal =		1 << 10,
	NetCore =		1 << 11,
	Computed =		1 << 23,
};
DEFINE_ENUM_FLAG_OPERATORS(ProcessAttributes);

enum class ProcessFlags {
	None,
	New =			1 << 0,
	Terminated =	1 << 1,
};
DEFINE_ENUM_FLAG_OPERATORS(ProcessFlags);

struct ProcessInfoEx : ProcessInfo {
	ProcessFlags Flags{ ProcessFlags::None };
	ProcessAttributes Attributes{ ProcessAttributes::None };
};

