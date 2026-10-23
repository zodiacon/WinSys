#pragma once

#include <string>
#include <vector>
#include <memory>
#include "Keys.h"

namespace WinSys {
	using namespace std;

	struct ThreadInfo;

	struct ProcessInfo {

		const SYSTEM_PROCESS_INFORMATION* NativeInfo{ nullptr };
		const SYSTEM_PROCESS_INFORMATION_EXTENSION* ExtendedInfo{ nullptr };
		PCWSTR m_PackageFullName{ nullptr };

		template<typename TProcessInfo, typename TThreadInfo>
		friend class ProcessManager;

		const wstring& GetImageName() const { return m_ProcessName; }
		const wstring& GetNativeImagePath() const { return m_NativeImagePath; }
		const vector<shared_ptr<ThreadInfo>>& GetThreads() const;
		const wstring& GetUserName() const;

		int BasePriority;
		uint32_t Id;
		uint32_t ParentId;
		int32_t CPU;
		int32_t KernelCPU;

		ProcessOrThreadKey Key;

		void AddThread(shared_ptr<ThreadInfo> thread);
		void ClearThreads();

		// For a process that exited (ProcessManager::GetTerminatedProcesses), before the next Update(): copies its
		// snapshot entry (the process, its threads and the extension) into a buffer of its own and points NativeInfo,
		// ExtendedInfo and the package name there, so it can still be shown after the snapshot buffer is reused. Its
		// thread objects are dropped, their pointers being the snapshot's. Once only; later calls do nothing
		void Detach();

	private:
		unique_ptr<BYTE[]> m_Detached;	// the entry, after Detach
		wstring m_ProcessName;
		wstring m_NativeImagePath;
		mutable std::wstring m_UserName;
		vector<shared_ptr<ThreadInfo>> m_threads;
	};
}

