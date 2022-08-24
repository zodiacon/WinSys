// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define PHNT_MODE 1
#define PHNT_VERSION PHNT_THRESHOLD
#define _HAS_EXCEPTIONS 0

#define STATUS_BUFFER_TOO_SMALL (0xC0000023)

#include <Windows.h>
#include <shellscalingapi.h>
#include <strsafe.h>
#include <string>
#include <vector>
#include <memory>
#include <vds.h>
#include <optional>
#include <Psapi.h>
#include <VersionHelpers.h>
#include <array>
#include <assert.h>
#include <unordered_map>
#include <shellapi.h>
#include <sddl.h>
#include <wil\resource.h>
#include <wil\com.h>
#include <phnt_windows.h>
#include <phnt.h>

#endif //PCH_H
