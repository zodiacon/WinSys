#pragma once

#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <unordered_map>
#include <wil/resource.h>

namespace WinSys {
	// an installed WSL distribution (HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss)
	struct WslDistro {
		std::wstring Name;
		std::wstring BasePath;
		uint32_t Version{ 2 };	// 1: WSL 1 (its processes are Windows pico processes), 2: in the WSL 2 VM
		bool Default{ false };
	};

	// a Linux process of a distribution, from its /proc
	struct WslProcess {
		uint32_t Pid{ 0 }, ParentPid{ 0 };
		std::wstring Name;		// comm: at most 15 characters, as the kernel keeps it
		wchar_t State{ L'?' };	// R, S, D, Z, T, t, X, I...
		uint32_t Uid{ UINT32_MAX };	// the real user ID; UINT32_MAX if not read
		std::wstring User;		// from the distribution's /etc/passwd; the ID as text if not there
		uint64_t UserTicks{ 0 }, SystemTicks{ 0 };	// clock ticks (WslSystem::ClockTicks a second)
		uint32_t Threads{ 0 };
		uint64_t StartTicks{ 0 };	// clock ticks after the (VM's) boot
		uint64_t VirtualBytes{ 0 }, ResidentBytes{ 0 };
		std::wstring CommandLine;	// its arguments separated by spaces (the first 512 bytes); empty for a zombie

		// the process's start as a Windows FILETIME, from the frame's uptime and the time it was read
		[[nodiscard]] int64_t StartTime(double uptimeSeconds, int64_t readTime, uint32_t clockTicks) const;
	};

	// a thread of a Linux process, from /proc/<pid>/task/<tid>/stat (the main thread's ID is the process's)
	struct WslThread {
		uint32_t Tid{ 0 }, Pid{ 0 };
		std::wstring Name;		// its comm (the process's unless the thread named itself)
		wchar_t State{ L'?' };
		uint64_t UserTicks{ 0 }, SystemTicks{ 0 };
		uint64_t StartTicks{ 0 };
	};

	// what the helper says once, when it starts
	struct WslSystem {
		uint32_t ClockTicks{ 100 }, Processors{ 1 }, PageSize{ 4096 };
		uint32_t HelperPid{ 0 };	// the helper's shell, left out of the frames with its children and its WSL session
		std::unordered_map<uint32_t, std::wstring> Users;	// /etc/passwd: user ID to name
	};

	// a snapshot of a distribution's processes
	struct WslFrame {
		double UptimeSeconds{ 0 };
		uint64_t CpuTotalTicks{ 0 }, CpuIdleTicks{ 0 };	// /proc/stat's cpu line: all processors, idle and iowait for idle
		uint64_t MemTotal{ 0 }, MemAvailable{ 0 };	// bytes (the VM's, shared by its distributions)
		int64_t ReadTime{ 0 };	// FILETIME, when the frame arrived
		std::vector<WslProcess> Processes;
		// the processes' threads, when the request asked for them (HasThreads)
		bool HasThreads{ false };
		std::vector<WslThread> Threads;
	};

	//
	// The helper's protocol, apart from the process for the tests: a shell loop in the distribution that prints its
	// system's constants and users once ("#K <clock ticks> <processors> <page size> <its PID>", "#P" and /etc/passwd,
	// "#R"), then a frame for every line it reads ("#F" uptime, /proc/stat's cpu line, MemTotal and MemAvailable; "#S"
	// every /proc/<pid>/stat; "#U" every Uid line of /proc/<pid>/status, by grep -H; "#C" every cmdline by head -c 512,
	// with head's "==> file <==" headers and the NULs made spaces; for a request line "t", "#T" and every
	// /proc/<pid>/task/<tid>/stat by head -n 1, with its headers; "#E"). It ends when its input closes.
	//
	struct WslProtocol final {
		// the script for /bin/sh -c: one line without double quotes, so it goes through wsl.exe's command line as one
		// argument
		[[nodiscard]] static std::wstring Script();
		// the start, "#K" to "#R"; false if it isn't one
		static bool ParseHeader(std::string_view text, WslSystem& system);
		// a frame, "#F" to "#E" (the markers included or not); the helper, its children and its WSL session processes
		// (its Relay and SessionLeader) left out; nothing if it isn't one
		[[nodiscard]] static std::optional<WslFrame> ParseFrame(std::string_view text, WslSystem const& system);
		// a /proc/<pid>/stat line; nothing if it isn't one
		[[nodiscard]] static std::optional<WslProcess> ParseStat(std::string_view line, uint32_t pageSize);
		// "Running", "Sleeping", "Disk sleep", "Zombie", "Stopped"...
		[[nodiscard]] static PCWSTR StateName(wchar_t state);
	};

	//
	// The installed distributions and which run, and signals to a distribution's processes, through wsl.exe (a
	// distribution that isn't running isn't started).
	//
	struct WslDistros final {
		[[nodiscard]] static std::vector<WslDistro> Enum();
		// the running distributions' names (wsl.exe --list --running --quiet, about 0.1 s); nothing if wsl.exe can't run
		[[nodiscard]] static std::optional<std::vector<std::wstring>> GetRunning();
		// sends a signal (kill -s <name>: TERM, KILL...) as root in the distribution; false with wsl.exe's or kill's
		// message in error
		static bool Signal(std::wstring const& distro, uint32_t pid, PCWSTR signal, std::wstring& error);
	};

	//
	// A distribution's processes, from the helper (WslProtocol) run in it by wsl.exe -d <distro> --exec /bin/sh -c,
	// its output read on a thread of the monitor's own. Request asks for a frame, TakeFrame takes the last one that
	// arrived (each refresh takes the frame its previous request made, so a slow distribution delays the rows by a
	// refresh and never blocks the caller). The helper keeps the distribution from idling out while it runs; Stop (and
	// the destructor) closes its input, which ends it.
	//
	class WslProcessMonitor {
	public:
		WslProcessMonitor() = default;
		WslProcessMonitor(WslProcessMonitor const&) = delete;
		WslProcessMonitor& operator=(WslProcessMonitor const&) = delete;
		~WslProcessMonitor();

		// starts the helper; false with the last error if wsl.exe can't start
		bool Start(std::wstring const& distro);
		void Stop();
		// the helper runs (wsl.exe hasn't exited: the distribution shutting down ends it)
		[[nodiscard]] bool IsRunning() const;
		[[nodiscard]] std::wstring const& GetDistro() const {
			return m_Distro;
		}
		// the start's constants and users; nothing until the helper said them
		[[nodiscard]] std::optional<WslSystem> GetSystem() const;
		// asks the helper for a frame, with the processes' threads or not
		void Request(bool threads = false);
		// the last frame that arrived since the last call; nothing if none did
		[[nodiscard]] std::optional<WslFrame> TakeFrame();

	private:
		static DWORD WINAPI ReaderThread(void* param);
		void Read();

		std::wstring m_Distro;
		wil::unique_handle m_Process, m_Input, m_Output, m_Thread;
		mutable wil::srwlock m_Lock;
		std::optional<WslSystem> m_System;
		std::optional<WslFrame> m_Frame;
	};
}
