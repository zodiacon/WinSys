#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define PHNT_MODE 1
#define PHNT_VERSION PHNT_THRESHOLD
#define _HAS_EXCEPTIONS 0

#define __ImageBase __ImageBase_phnt	// phnt declares it const, WIL doesn't
#include <phnt_windows.h>
#include <phnt.h>
#undef __ImageBase

#include <ShellScalingApi.h>
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


