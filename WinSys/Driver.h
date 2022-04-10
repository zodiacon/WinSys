#pragma once

namespace WinSys {
	class Driver final {
	public:
		static bool Install(PCWSTR sysFilePath, PCWSTR serviceName = nullptr);
		static bool Start(PCWSTR serviceName = nullptr);
		static bool Stop(PCWSTR serviceName = nullptr);

		bool Open();
		operator bool() const {
			return IsOpen();
		}
		bool IsOpen() const;

		HANDLE DuplicateHandle(DWORD pid, HANDLE handle, ACCESS_MASK access = 0, DWORD flags = DUPLICATE_SAME_ACCESS) const;
		HANDLE OpenProcess(ACCESS_MASK access, DWORD pid) const;
		HANDLE OpenThread(ACCESS_MASK access, DWORD pid) const;
		HANDLE OpenObjectByName(ACCESS_MASK access, PCWSTR name, USHORT typeIndex) const;
		DWORD GetVersion() const;

	private:
		HANDLE OpenProcessThreadCommon(DWORD icotl, ACCESS_MASK access, DWORD id) const;

	private:
		wil::unique_hfile m_hDevice;
	};
}

