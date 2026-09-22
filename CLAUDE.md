# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

WinSys is a C++20 library for low-level Windows development, extracted from the SystemExplorer project. It wraps native (NT) APIs for processes, threads, services, drivers, tokens/SIDs, LSA, kernel/process modules, and the Virtual Disk Service (VDS). Everything lives in the `WinSys` namespace.

## Build

Visual Studio / MSBuild solution (`WinSys.sln`). Primary target is `x64` (the solution maps ARM/ARM64 onto x64 configs). Toolset is v145 (VS 2026) with Windows SDK 10.0.26100.0 (see the phnt note below); the Win32 configs of the console projects still use v143.

```powershell
msbuild WinSys.sln /p:Configuration=Debug /p:Platform=x64
msbuild WinSys\WinSys.vcxproj /p:Configuration=Release /p:Platform=x64   # library only
```

Dependencies:
- **phnt** (native API headers): consumed via vcpkg (user-wide integration, no manifest in the repo). The local `phnt` copy was removed; the stale `.\phnt` entry in `AdditionalIncludeDirectories` is harmless.
  - Keep `WindowsTargetPlatformVersion` pinned to `10.0.26100.0`, not `10.0` (latest). SDK 10.0.28000 enlarged `XSTATE_CONFIGURATION` and reordered `KUSER_SHARED_DATA`, so phnt's `KUSER_SHARED_DATA` offset asserts in `ntexapi.h` fail (C2118 "negative subscript"). As of phnt 2025-02-05 (vcpkg) and upstream master 2026-03-26 this is unfixed.
  - The `pch.h` files wrap the phnt includes in `#define __ImageBase __ImageBase_phnt` / `#undef`, because phnt declares `__ImageBase` `const` and WIL doesn't (C2373 otherwise). Keep this wrapper in any new `pch.h` that includes both.
- **WIL** (`wil/resource.h`, `wil/com.h`): resolved from vcpkg. The console projects also reference NuGet `Microsoft.Windows.ImplementationLibrary` in `packages/` (`packages.config`); restore with `nuget restore WinSys.sln` if missing.
- `.gitmodules` lists a `WTLHelper` submodule, but it is not checked out or used by any project.

There is no unit-test framework. `WinSysCon` (process/thread enumeration + a `PerfTest` timing loop) and `VdsTest` (VDS enumeration) are console apps used for manual testing. Many APIs return more data when run elevated.

## Projects

- **WinSys**: static library, the core. Header-only pieces (notably `ProcessManager.h`) are included directly by consumers, which add `WinSys\` to their include path and link `ntdll`.
- **KWinSys**: WDM kernel driver (WDK toolset, `WindowsKernelModeDriver10.0`). Lets user mode open processes/threads/tokens/objects by address or name and duplicate handles when normal APIs are denied. `KWinSysPublic.h` holds the IOCTL codes and packed request structs shared with user mode; `WinSys/Driver.cpp` is the user-mode client that installs/loads the driver as the `KWinSys` service and issues the IOCTLs. Changes to the protocol must be made in both places.
- **WinSysCon**, **VdsTest**: test consoles referencing WinSys.

## Architecture notes

- **Native API usage**: `pch.h` defines `PHNT_MODE 1` / `PHNT_VERSION PHNT_THRESHOLD` and includes `phnt_windows.h` + `phnt.h` *instead of* `windows.h`. Don't include `windows.h` or `winternl.h` directly ahead of it. Exceptions are disabled (`_HAS_EXCEPTIONS 0`), so errors are reported through return values (`bool`, `nullptr`, `std::optional`, status codes), not throws.
- **ProcessManager<TProcessInfo, TThreadInfo>** (`ProcessManager.h`, header-only template): takes snapshots with `NtQuerySystemInformation` (`SystemFullProcessInformation` when elevated, else `SystemExtendedProcessInformation`). Callers can subclass `ProcessInfo`/`ThreadInfo` to attach extra data. Each `Update()` diffs against the previous snapshot by `ProcessOrThreadKey` (id + create time, see `Keys.h`) to produce new/terminated lists and CPU percentages.
  - `ProcessInfo::NativeInfo`/`ExtendedInfo` and `ThreadInfo`'s native pointers point **directly into the snapshot buffer**. The manager keeps two buffers (`m_Buffer[2]`, alternating `m_BufIndex`) so the previous snapshot's pointers stay valid for one update cycle. Preserve this double-buffering when changing the update logic, and don't cache these pointers across more than one `Update()`.
- **Handle-owning wrappers** (`Process`, `Thread`, `Token`, `Service`, `ServiceManager`, `Driver`) hold WIL RAII handles (`wil::unique_handle`, `wil::unique_schandle`, and so on) and are typically created through static factory methods like `OpenById`, not public constructors.
- **VDS** (`VirtualDiskService`, `VdsProvider`, `VdsVolume`) is COM-based and uses `wil::com_ptr`. The caller must initialize COM.

## Conventions

- Tabs for indentation, `m_` prefix for members, `s_` for statics, PascalCase methods, `[[nodiscard]]` on getters.
- Every `.cpp` in a project starts with `#include "pch.h"`.
- When adding a source file, register it in both the `.vcxproj` and the `.vcxproj.filters`.
