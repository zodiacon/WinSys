#pragma once

#include <string>
#include <vector>
#include <memory>
#include "Keys.h"

namespace WinSys {
	struct ThreadInfo;

	struct ProcessInfo {
		template<typename TProcessInfo, typename TThreadInfo>
		friend class ProcessManager;

		const std::wstring& GetImageName() const { return m_processName; }
		const std::wstring& GetPackageFullName() const { return m_packageFullName; }
		const std::wstring& GetNativeImagePath() const { return m_nativeImagePath; }
		const std::vector<std::shared_ptr<ThreadInfo>>& GetThreads() const;
		const std::wstring& GetUserName() const;

		int BasePriority;
		uint32_t Id;
		uint32_t ParentId;
		uint32_t HandleCount;
		uint32_t ThreadCount;
		uint32_t PeakThreads;
		uint32_t HardFaultCount; // since WIN7
		uint32_t SessionId;
		size_t VirtualSize;
		size_t PeakVirtualSize;
		int64_t CreateTime;
		int64_t UserTime;
		int64_t KernelTime;
		uint32_t PageFaultCount;
		size_t PeakWorkingSetSize;
		size_t WorkingSetSize;
		size_t PeakPagedPoolUsage;
		size_t PagedPoolUsage;
		size_t PeakNonPagedPoolUsage;
		size_t NonPagedPoolUsage;
		size_t PagefileUsage;
		size_t PeakPagefileUsage;
		size_t PrivatePageCount;
		int64_t ReadOperationCount;
		int64_t WriteOperationCount;
		int64_t OtherOperationCount;
		int64_t ReadTransferCount;
		int64_t WriteTransferCount;
		int64_t OtherTransferCount;
		uint64_t CycleTime; // since WIN7
		int64_t WorkingSetPrivateSize; // since VISTA
		int32_t CPU;
		int32_t KernelCPU;
		uint32_t JobObjectId;
		BYTE UserSid[SECURITY_MAX_SID_SIZE];

		ProcessOrThreadKey Key;

		void AddThread(std::shared_ptr<ThreadInfo> thread);
		void ClearThreads();

	private:
		std::wstring m_processName;
		std::wstring m_nativeImagePath;
		std::wstring m_packageFullName;
		mutable std::wstring m_userName;
		std::vector<std::shared_ptr<ThreadInfo>> m_threads;
	};
}

