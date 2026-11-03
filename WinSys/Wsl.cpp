#include "pch.h"
#include "Wsl.h"
#include <algorithm>
#include <unordered_set>

namespace WinSys {
	namespace {
		std::wstring FromUtf8(std::string_view text) {
			if (text.empty())
				return L"";
			int count = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0);
			std::wstring result(count, L'\0');
			::MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), result.data(), count);
			return result;
		}

		// the next line (without its '\n') and the rest after it
		bool NextLine(std::string_view& text, std::string_view& line) {
			if (text.empty())
				return false;
			auto end = text.find('\n');
			line = text.substr(0, end);
			text = end == std::string_view::npos ? std::string_view() : text.substr(end + 1);
			if (!line.empty() && line.back() == '\r')
				line.remove_suffix(1);
			return true;
		}

		uint64_t ToNumber(std::string_view text) {
			uint64_t value = 0;
			for (auto ch : text) {
				if (ch < '0' || ch > '9')
					break;
				value = value * 10 + (ch - '0');
			}
			return value;
		}

		// the space separated fields
		std::vector<std::string_view> Split(std::string_view text) {
			std::vector<std::string_view> fields;
			size_t i = 0;
			while (i < text.size()) {
				while (i < text.size() && (text[i] == ' ' || text[i] == '\t'))
					i++;
				auto start = i;
				while (i < text.size() && text[i] != ' ' && text[i] != '\t')
					i++;
				if (i > start)
					fields.push_back(text.substr(start, i - start));
			}
			return fields;
		}

		// the pid in "/proc/<pid>/..."
		uint32_t PidOfPath(std::string_view path) {
			if (!path.starts_with("/proc/"))
				return 0;
			return (uint32_t)ToNumber(path.substr(6));
		}

		int64_t Now() {
			int64_t now;
			::GetSystemTimeAsFileTime((FILETIME*)&now);
			return now;
		}

		// starts wsl.exe with its standard handles, inheriting only those: the poll's and the helpers' pipes are made
		// on different threads, and a long-lived helper that inherited the poll's pipe would keep its output from ending
		bool StartWsl(std::wstring& cmd, HANDLE input, HANDLE output, HANDLE error, PROCESS_INFORMATION& pi) {
			HANDLE handles[3];
			DWORD count = 0;
			for (auto h : { input, output, error })
				if (h && std::find(handles, handles + count, h) == handles + count)
					handles[count++] = h;
			SIZE_T size = 0;
			::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
			std::vector<BYTE> buffer(size);
			auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
			if (!::InitializeProcThreadAttributeList(attributes, 1, 0, &size))
				return false;
			bool ok = ::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, count * sizeof(HANDLE), nullptr, nullptr);
			if (ok) {
				STARTUPINFOEX si{ { sizeof(si) } };
				si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
				si.StartupInfo.hStdInput = input;
				si.StartupInfo.hStdOutput = output;
				si.StartupInfo.hStdError = error;
				si.lpAttributeList = attributes;
				ok = ::CreateProcess(nullptr, cmd.data(), nullptr, nullptr, count > 0, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
					nullptr, nullptr, &si.StartupInfo, &pi);
			}
			auto error2 = ::GetLastError();
			::DeleteProcThreadAttributeList(attributes);
			::SetLastError(error2);
			return ok;
		}

		// runs wsl.exe with the arguments; its output (stdout and stderr) and exit code; false if it can't start or
		// doesn't finish in time
		bool RunWsl(std::wstring const& arguments, std::string& output, DWORD& exitCode, DWORD timeout) {
			SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
			wil::unique_handle read, write;
			if (!::CreatePipe(read.addressof(), write.addressof(), &sa, 0))
				return false;
			::SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0);
			std::wstring cmd = L"wsl.exe " + arguments;
			PROCESS_INFORMATION pi{};
			if (!StartWsl(cmd, nullptr, write.get(), write.get(), pi))
				return false;
			wil::unique_handle process(pi.hProcess), thread(pi.hThread);
			write.reset();
			char buffer[4096];
			DWORD bytes;
			auto deadline = ::GetTickCount64() + timeout;
			while (::ReadFile(read.get(), buffer, sizeof(buffer), &bytes, nullptr) && bytes > 0) {
				output.append(buffer, bytes);
				if (::GetTickCount64() > deadline)
					break;
			}
			if (::WaitForSingleObject(process.get(), timeout) != WAIT_OBJECT_0) {
				::TerminateProcess(process.get(), 1);
				::SetLastError(ERROR_TIMEOUT);
				return false;
			}
			::GetExitCodeProcess(process.get(), &exitCode);
			return true;
		}

		// wsl.exe writes UTF-16 by default (UTF-8 with WSL_UTF8=1)
		std::wstring DecodeWslOutput(std::string const& output) {
			if (output.size() >= 2 && output.size() % 2 == 0 && output[1] == 0)
				return std::wstring((wchar_t const*)output.data(), output.size() / 2);
			return FromUtf8(output);
		}
	}

	int64_t WslProcess::StartTime(double uptimeSeconds, int64_t readTime, uint32_t clockTicks) const {
		if (!clockTicks)
			return 0;
		double age = uptimeSeconds - double(StartTicks) / clockTicks;
		return readTime - int64_t(age * 10'000'000);
	}

	std::wstring WslProtocol::Script() {
		return L"echo '#K' $(getconf CLK_TCK 2>/dev/null || echo 100) $(grep -c '^cpu[0-9]' /proc/stat) $(getconf PAGESIZE 2>/dev/null || echo 4096) $$; "
			L"echo '#P'; cat /etc/passwd 2>/dev/null; echo '#R'; "
			L"while read -r x; do "
			L"echo '#F'; cat /proc/uptime; head -n 1 /proc/stat; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo; "
			L"echo '#S'; cat /proc/[0-9]*/stat 2>/dev/null; "
			L"echo '#U'; grep -H '^Uid' /proc/[0-9]*/status 2>/dev/null; "
			L"echo '#C'; head -c 512 /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' '; echo; "
			L"echo '#E'; done";
	}

	bool WslProtocol::ParseHeader(std::string_view text, WslSystem& system) {
		std::string_view line;
		bool started = false, users = false;
		while (NextLine(text, line)) {
			if (line.starts_with("#K ")) {
				auto f = Split(line.substr(3));
				if (f.size() < 4)
					return false;
				system.ClockTicks = std::max<uint32_t>(1, (uint32_t)ToNumber(f[0]));
				system.Processors = std::max<uint32_t>(1, (uint32_t)ToNumber(f[1]));
				system.PageSize = std::max<uint32_t>(512, (uint32_t)ToNumber(f[2]));
				system.HelperPid = (uint32_t)ToNumber(f[3]);
				started = true;
			}
			else if (line == "#P")
				users = true;
			else if (line == "#R")
				return started;
			else if (users) {
				// name:password:uid:...
				auto first = line.find(':');
				auto second = first == std::string_view::npos ? first : line.find(':', first + 1);
				if (second != std::string_view::npos)
					system.Users[(uint32_t)ToNumber(line.substr(second + 1))] = FromUtf8(line.substr(0, first));
			}
		}
		return false;
	}

	std::optional<WslProcess> WslProtocol::ParseStat(std::string_view line, uint32_t pageSize) {
		// "pid (comm) state ppid ...": comm may hold spaces and parentheses, so it ends at the last ')'
		auto open = line.find(" (");
		auto close = line.rfind(')');
		if (open == std::string_view::npos || close == std::string_view::npos || close < open)
			return {};
		WslProcess p;
		p.Pid = (uint32_t)ToNumber(line.substr(0, open));
		if (p.Pid == 0)
			return {};
		p.Name = FromUtf8(line.substr(open + 2, close - open - 2));
		// the fields after comm, from state (field 3): utime 14, stime 15, threads 20, starttime 22, vsize 23, rss 24
		auto f = Split(line.substr(close + 1));
		if (f.size() < 22)
			return {};
		p.State = (wchar_t)f[0][0];
		p.ParentPid = (uint32_t)ToNumber(f[1]);
		p.UserTicks = ToNumber(f[11]);
		p.SystemTicks = ToNumber(f[12]);
		p.Threads = (uint32_t)ToNumber(f[17]);
		p.StartTicks = ToNumber(f[19]);
		p.VirtualBytes = ToNumber(f[20]);
		p.ResidentBytes = ToNumber(f[21]) * pageSize;
		return p;
	}

	std::optional<WslFrame> WslProtocol::ParseFrame(std::string_view text, WslSystem const& system) {
		WslFrame frame;
		std::unordered_map<uint32_t, uint32_t> uids;
		std::unordered_map<uint32_t, std::wstring> commandLines;
		enum class Section { None, Header, Stat, Uid, Cmdline } section = Section::None;
		std::string_view line;
		bool ended = false, header = false;
		uint32_t cmdlinePid = 0;
		std::string cmdline;
		auto flushCmdline = [&] {
			if (cmdlinePid) {
				while (!cmdline.empty() && (cmdline.back() == ' ' || cmdline.back() == '\n'))
					cmdline.pop_back();
				commandLines[cmdlinePid] = FromUtf8(cmdline);
			}
			cmdlinePid = 0;
			cmdline.clear();
		};
		while (NextLine(text, line)) {
			if (line == "#F") {
				section = Section::Header;
				header = true;
				continue;
			}
			if (line == "#S" || line == "#U" || line == "#C" || line == "#E") {
				if (section == Section::Cmdline)
					flushCmdline();
				section = line == "#S" ? Section::Stat : line == "#U" ? Section::Uid : line == "#C" ? Section::Cmdline : Section::None;
				if (line == "#E") {
					ended = true;
					break;
				}
				continue;
			}
			switch (section) {
				case Section::Header:
				{
					auto f = Split(line);
					if (line.starts_with("cpu ")) {
						// user nice system idle iowait irq softirq steal...
						for (size_t i = 1; i < f.size() && i <= 8; i++) {
							auto value = ToNumber(f[i]);
							frame.CpuTotalTicks += value;
							if (i == 4 || i == 5)
								frame.CpuIdleTicks += value;
						}
					}
					else if (line.starts_with("MemTotal:") && f.size() >= 2)
						frame.MemTotal = ToNumber(f[1]) * 1024;
					else if (line.starts_with("MemAvailable:") && f.size() >= 2)
						frame.MemAvailable = ToNumber(f[1]) * 1024;
					else if (!f.empty() && frame.UptimeSeconds == 0) {
						// "12345.67 89012.34"
						std::string number(f[0]);
						frame.UptimeSeconds = ::strtod(number.c_str(), nullptr);
					}
					break;
				}
				case Section::Stat:
					if (auto p = ParseStat(line, system.PageSize))
						frame.Processes.push_back(std::move(*p));
					break;
				case Section::Uid:
				{
					// "/proc/123/status:Uid:\t1000\t1000\t1000\t1000"
					auto colon = line.find(":Uid:");
					if (colon != std::string_view::npos) {
						auto f = Split(line.substr(colon + 5));
						if (!f.empty())
							uids[PidOfPath(line)] = (uint32_t)ToNumber(f[0]);
					}
					break;
				}
				case Section::Cmdline:
					// "==> /proc/123/cmdline <==" starts a process's; the text follows (it may be empty)
					if (line.starts_with("==> /proc/") && line.ends_with(" <==")) {
						flushCmdline();
						cmdlinePid = PidOfPath(line.substr(4));
					}
					else if (cmdlinePid) {
						if (!cmdline.empty())
							cmdline += ' ';
						cmdline += line;
					}
					break;
			}
		}
		if (!ended || !header)
			return {};

		// the helper, the processes it runs (cat, grep, head, tr), and its WSL session (its Relay and SessionLeader)
		std::unordered_set<uint32_t> hidden;
		if (system.HelperPid) {
			hidden.insert(system.HelperPid);
			for (auto& p : frame.Processes)
				if (p.ParentPid == system.HelperPid)
					hidden.insert(p.Pid);
			auto find = [&](uint32_t pid) {
				return std::find_if(frame.Processes.begin(), frame.Processes.end(), [&](auto& p) { return p.Pid == pid; });
			};
			if (auto helper = find(system.HelperPid); helper != frame.Processes.end()) {
				if (auto relay = find(helper->ParentPid); relay != frame.Processes.end() && relay->Name.starts_with(L"Relay(")) {
					hidden.insert(relay->Pid);
					if (auto leader = find(relay->ParentPid); leader != frame.Processes.end() && leader->Name == L"SessionLeader")
						hidden.insert(leader->Pid);
				}
			}
		}
		std::erase_if(frame.Processes, [&](auto& p) { return hidden.contains(p.Pid); });
		for (auto& p : frame.Processes) {
			if (auto it = uids.find(p.Pid); it != uids.end()) {
				p.Uid = it->second;
				auto user = system.Users.find(p.Uid);
				p.User = user != system.Users.end() ? user->second : std::to_wstring(p.Uid);
			}
			if (auto it = commandLines.find(p.Pid); it != commandLines.end())
				p.CommandLine = std::move(it->second);
		}
		return frame;
	}

	PCWSTR WslProtocol::StateName(wchar_t state) {
		switch (state) {
			case L'R': return L"Running";
			case L'S': return L"Sleeping";
			case L'D': return L"Disk sleep";
			case L'Z': return L"Zombie";
			case L'T': return L"Stopped";
			case L't': return L"Tracing stop";
			case L'X': case L'x': return L"Dead";
			case L'I': return L"Idle";
			case L'P': return L"Parked";
			case L'W': return L"Waking";
			case L'K': return L"Wakekill";
		}
		return L"";
	}

	std::vector<WslDistro> WslDistros::Enum() {
		std::vector<WslDistro> distros;
		HKEY hKey;
		if (::RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Lxss", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
			return distros;
		wil::unique_hkey key(hKey);
		WCHAR defaultId[64]{};
		DWORD size = sizeof(defaultId);
		::RegGetValue(key.get(), nullptr, L"DefaultDistribution", RRF_RT_REG_SZ, nullptr, defaultId, &size);
		WCHAR name[64];
		for (DWORD i = 0; ; i++) {
			DWORD len = _countof(name);
			if (::RegEnumKeyEx(key.get(), i, name, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
				break;
			WslDistro distro;
			WCHAR text[MAX_PATH]{};
			size = sizeof(text);
			if (::RegGetValue(key.get(), name, L"DistributionName", RRF_RT_REG_SZ, nullptr, text, &size) != ERROR_SUCCESS)
				continue;
			distro.Name = text;
			size = sizeof(text);
			text[0] = 0;
			if (::RegGetValue(key.get(), name, L"BasePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr, text, &size) == ERROR_SUCCESS)
				distro.BasePath = text;
			DWORD version = 2;
			size = sizeof(version);
			if (::RegGetValue(key.get(), name, L"Version", RRF_RT_REG_DWORD, nullptr, &version, &size) == ERROR_SUCCESS)
				distro.Version = version;
			distro.Default = ::_wcsicmp(name, defaultId) == 0;
			distros.push_back(std::move(distro));
		}
		return distros;
	}

	std::optional<std::vector<std::wstring>> WslDistros::GetRunning() {
		std::string output;
		DWORD code = 0;
		if (!RunWsl(L"--list --running --quiet", output, code, 10000))
			return {};
		std::vector<std::wstring> names;
		// with nothing running it says so and exits with an error
		if (code != 0)
			return names;
		auto text = DecodeWslOutput(output);
		size_t start = 0;
		while (start < text.size()) {
			auto end = text.find(L'\n', start);
			auto name = text.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
			while (!name.empty() && (name.back() == L'\r' || name.back() == L' ' || name.back() == 0))
				name.pop_back();
			while (!name.empty() && (name.front() == 0xFEFF || name.front() == L' '))
				name.erase(0, 1);
			if (!name.empty())
				names.push_back(name);
			if (end == std::wstring::npos)
				break;
			start = end + 1;
		}
		return names;
	}

	bool WslDistros::Signal(std::wstring const& distro, uint32_t pid, PCWSTR signal, std::wstring& error) {
		std::string output;
		DWORD code = 0;
		if (!RunWsl(L"-d " + distro + L" -u root --exec kill -s " + signal + L" " + std::to_wstring(pid), output, code, 15000)) {
			error = L"wsl.exe didn't run";
			return false;
		}
		if (code == 0)
			return true;
		error = DecodeWslOutput(output);
		while (!error.empty() && (error.back() == L'\n' || error.back() == L'\r'))
			error.pop_back();
		if (error.empty())
			error = L"kill failed with exit code " + std::to_wstring(code);
		return false;
	}

	WslProcessMonitor::~WslProcessMonitor() {
		Stop();
	}

	bool WslProcessMonitor::Start(std::wstring const& distro) {
		// wsl.exe parses its own command line: a quoted name keeps its quotes (and names have no spaces)
		Stop();
		m_Distro = distro;
		SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
		wil::unique_handle inRead, inWrite, outRead, outWrite;
		if (!::CreatePipe(inRead.addressof(), inWrite.addressof(), &sa, 0) || !::CreatePipe(outRead.addressof(), outWrite.addressof(), &sa, 0))
			return false;
		// the ends kept here aren't inherited
		::SetHandleInformation(inWrite.get(), HANDLE_FLAG_INHERIT, 0);
		::SetHandleInformation(outRead.get(), HANDLE_FLAG_INHERIT, 0);
		std::wstring cmd = L"wsl.exe -d " + distro + L" --exec /bin/sh -c \"" + WslProtocol::Script() + L"\"";
		PROCESS_INFORMATION pi{};
		if (!StartWsl(cmd, inRead.get(), outWrite.get(), nullptr, pi))
			return false;
		m_Process.reset(pi.hProcess);
		::CloseHandle(pi.hThread);
		m_Input = std::move(inWrite);
		m_Output = std::move(outRead);
		m_Thread.reset(::CreateThread(nullptr, 0, ReaderThread, this, 0, nullptr));
		if (!m_Thread) {
			auto error = ::GetLastError();
			Stop();
			::SetLastError(error);
			return false;
		}
		return true;
	}

	void WslProcessMonitor::Stop() {
		// the helper's read ends: it exits, wsl.exe with it, and the reader sees the end of its output
		m_Input.reset();
		if (m_Process && ::WaitForSingleObject(m_Process.get(), 3000) != WAIT_OBJECT_0)
			::TerminateProcess(m_Process.get(), 1);
		if (m_Thread) {
			if (::WaitForSingleObject(m_Thread.get(), 3000) != WAIT_OBJECT_0) {
				// a read that doesn't return: its pipe goes, which ends it
				::CancelSynchronousIo(m_Thread.get());
				::WaitForSingleObject(m_Thread.get(), 1000);
			}
			m_Thread.reset();
		}
		m_Output.reset();
		m_Process.reset();
		auto lock = m_Lock.lock_exclusive();
		m_System.reset();
		m_Frame.reset();
	}

	bool WslProcessMonitor::IsRunning() const {
		return m_Process && ::WaitForSingleObject(m_Process.get(), 0) == WAIT_TIMEOUT;
	}

	std::optional<WslSystem> WslProcessMonitor::GetSystem() const {
		auto lock = m_Lock.lock_shared();
		return m_System;
	}

	void WslProcessMonitor::Request() {
		if (!m_Input)
			return;
		DWORD written;
		if (!::WriteFile(m_Input.get(), "\n", 1, &written, nullptr))
			m_Input.reset();
	}

	std::optional<WslFrame> WslProcessMonitor::TakeFrame() {
		auto lock = m_Lock.lock_exclusive();
		auto frame = std::move(m_Frame);
		m_Frame.reset();
		return frame;
	}

	DWORD WINAPI WslProcessMonitor::ReaderThread(void* param) {
		static_cast<WslProcessMonitor*>(param)->Read();
		return 0;
	}

	void WslProcessMonitor::Read() {
		std::string buffer;
		std::optional<WslSystem> system;
		char chunk[16384];
		DWORD bytes;
		while (::ReadFile(m_Output.get(), chunk, sizeof(chunk), &bytes, nullptr) && bytes > 0) {
			buffer.append(chunk, bytes);
			for (;;) {
				if (!system) {
					auto end = buffer.find("\n#R\n");
					if (end == std::string::npos)
						break;
					WslSystem s;
					if (WslProtocol::ParseHeader(std::string_view(buffer).substr(0, end + 4), s)) {
						system = s;
						auto lock = m_Lock.lock_exclusive();
						m_System = s;
					}
					buffer.erase(0, end + 4);
					continue;
				}
				auto end = buffer.find("\n#E\n");
				if (end == std::string::npos)
					break;
				auto frame = WslProtocol::ParseFrame(std::string_view(buffer).substr(0, end + 4), *system);
				buffer.erase(0, end + 4);
				if (frame) {
					frame->ReadTime = Now();
					auto lock = m_Lock.lock_exclusive();
					m_Frame = std::move(frame);
				}
			}
		}
	}
}
