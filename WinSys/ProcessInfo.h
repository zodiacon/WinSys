#pragma once

#include <string>
#include <vector>
#include <memory>
#include "Keys.h"

namespace WinSys {
	struct ThreadInfo;

	struct ProcessInfo {
		const SYSTEM_PROCESS_INFORMATION* NativeInfo{ nullptr };
		const SYSTEM_PROCESS_INFORMATION_EXTENSION* ExtendedInfo{ nullptr };
		PCWSTR m_PackageFullName{ nullptr };

		template<typename TProcessInfo, typename TThreadInfo>
		friend class ProcessManager;

		const std::wstring& GetImageName() const { return m_ProcessName; }
		const std::wstring& GetNativeImagePath() const { return m_NativeImagePath; }
		const std::vector<std::shared_ptr<ThreadInfo>>& GetThreads() const;
		const std::wstring& GetUserName() const;

		int BasePriority;
		uint32_t Id;
		uint32_t ParentId;
		int32_t CPU;
		int32_t KernelCPU;

		ProcessOrThreadKey Key;

		void AddThread(std::shared_ptr<ThreadInfo> thread);
		void ClearThreads();

	private:
		std::wstring m_ProcessName;
		std::wstring m_NativeImagePath;
		mutable std::wstring m_UserName;
		std::vector<std::shared_ptr<ThreadInfo>> m_threads;
	};
}

