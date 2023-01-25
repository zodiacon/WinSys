#pragma once

#include <memory>
#include <vector>
#include <type_traits>
#include <unordered_map>
#include <wil\resource.h>
#include "Keys.h"
#include "ProcessInfo.h"
#include "ThreadInfo.h"
#include "Processes.h"
#include "Enums.h"
#include "SecurityHelper.h"

#ifdef __cplusplus
#if _MSC_VER >= 1300
#define TYPE_ALIGNMENT( t ) __alignof(t)
#endif
#else
#define TYPE_ALIGNMENT( t ) \
	FIELD_OFFSET( struct { char x; t test; }, test )
#endif

#ifdef EnumProcesses
#undef EnumProcesses
#endif

namespace WinSys {
	template<typename TProcessInfo = ProcessInfo, typename TThreadInfo = ThreadInfo>
	class ProcessManager {
		static_assert(std::is_base_of_v<ProcessInfo, TProcessInfo>);
		static_assert(std::is_base_of_v<ThreadInfo, TThreadInfo>);
	public:
		ProcessManager(const ProcessManager&) = delete;
		ProcessManager& operator=(const ProcessManager&) = delete;

		uint32_t EnumProcesses() {
			return EnumProcesses(false, 0);
		}
		uint32_t EnumProcessesAndThreads(uint32_t pid = 0) {
			return EnumProcesses(true, pid);
		}

		[[nodiscard]] std::vector<std::shared_ptr<TProcessInfo>> const& GetTerminatedProcesses() const {
			return m_TerminatedProcesses;
		}
		[[nodiscard]] std::vector<std::shared_ptr<TProcessInfo>> const& GetNewProcesses() const {
			return m_NewProcesses;
		}

		[[nodiscard]] std::wstring GetProcessNameById(uint32_t pid) const {
			if (pid == 0)
				return L"";
			auto pi = GetProcessById(pid);
			return pi ? pi->GetImageName() : L"";
		}

		ProcessManager() {
			if (s_TotalProcessors == 0) {
				s_TotalProcessors = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
				s_IsElevated = SecurityHelper::IsRunningElevated();
			}
		}

		uint32_t EnumProcesses(bool includeThreads, uint32_t pid) {
			std::vector<std::shared_ptr<TProcessInfo>> processes;
			processes.reserve(m_Processes.empty() ? 512 : m_Processes.size() + 10);
			ProcessMap processesByKey;
			processesByKey.reserve(m_Processes.size() == 0 ? 512 : m_Processes.size() + 10);
			m_ProcessesById.clear();
			m_ProcessesById.reserve(m_Processes.capacity());

			m_NewProcesses.clear();

			ThreadMap threadsByKey;
			if (includeThreads) {
				threadsByKey.reserve(4096);
				m_NewThreads.clear();
				if (m_Threads.empty())
					m_NewThreads.reserve(4096);
				m_Threads.clear();
				m_ThreadsById.clear();
			}

			int size = 1 << 22;
			if(!m_Buffer)
				m_Buffer.reset((BYTE*)::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!m_Buffer)
				return 0;
			auto buffer = m_Buffer.get();

			ULONG len;

			// get timing info as close as possible to the API call

			LARGE_INTEGER ticks;
			::QueryPerformanceCounter(&ticks);
			auto delta = ticks.QuadPart - m_PrevTicks.QuadPart;

			NTSTATUS status;
			bool extended;
			if (s_IsElevated && IsWindows8OrGreater()) {
				status = NtQuerySystemInformation(SystemFullProcessInformation, buffer, size, &len);
				extended = true;
			}
			else {
				extended = false;
				status = NtQuerySystemInformation(SystemExtendedProcessInformation, buffer, size, &len);
			}
			if (NT_SUCCESS(status)) {
				auto p = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buffer);

				for (;;) {
					if (pid == 0 || pid == HandleToULong(p->UniqueProcessId)) {
						ProcessOrThreadKey key = { p->CreateTime.QuadPart, HandleToULong(p->UniqueProcessId) };
						std::shared_ptr<TProcessInfo> pi;
						if (auto it = m_processesByKey.find(key); it == m_processesByKey.end()) {
							// new process
							pi = BuildProcessInfo(p, includeThreads, threadsByKey, delta, pi, extended);
							m_NewProcesses.push_back(pi);
							pi->CPU = pi->KernelCPU = 0;
						}
						else {
							const auto& pi2 = it->second;
							auto kcpu = delta == 0 ? 0 : (int32_t)((p->KernelTime.QuadPart - pi2->NativeInfo->KernelTime.QuadPart) * 1000000 / delta / s_TotalProcessors);
							auto cpu = delta == 0 ? 0 : (int32_t)((p->KernelTime.QuadPart + p->UserTime.QuadPart - pi2->NativeInfo->UserTime.QuadPart - pi2->NativeInfo->KernelTime.QuadPart) * 1000000 / delta / s_TotalProcessors);
							pi = BuildProcessInfo(p, includeThreads, threadsByKey, delta, pi2, extended);
							pi->CPU = cpu;
							pi->KernelCPU = kcpu;

							// remove from known processes
							m_processesByKey.erase(key);
						}
						processes.push_back(pi);
						//
						// add process to maps
						//
						processesByKey.insert({ key, pi });
						m_ProcessesById.insert({ pi->Id, pi });
					}
					if (p->NextEntryOffset == 0)
						break;
					p = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>((BYTE*)p + p->NextEntryOffset);
				}
			}
			m_Processes = std::move(processes);

			//
			// remaining processes are terminated ones
			//
			m_TerminatedProcesses.clear();
			m_TerminatedProcesses.reserve(m_processesByKey.size());
			for (const auto& [key, pi] : m_processesByKey)
				m_TerminatedProcesses.push_back(pi);

			m_processesByKey = std::move(processesByKey);

			if (includeThreads) {
				m_TerminatedThreads.clear();
				m_TerminatedThreads.reserve(m_threadsByKey.size());
				for (const auto& [key, ti] : m_threadsByKey)
					m_TerminatedThreads.push_back(ti);

				m_threadsByKey = std::move(threadsByKey);
			}

			m_PrevTicks = ticks;

			return static_cast<uint32_t>(m_Processes.size());
		}

		[[nodiscard]] std::vector<std::shared_ptr<TProcessInfo>> const& GetProcesses() const {
			return m_Processes;
		}

		[[nodiscard]] std::shared_ptr<TProcessInfo> GetProcessInfo(int index) const {
			return m_Processes[index];
		}

		[[nodiscard]] std::shared_ptr<TProcessInfo> GetProcessById(uint32_t pid) const {
			auto it = m_ProcessesById.find(pid);
			return it == m_ProcessesById.end() ? nullptr : it->second;
		}

		[[nodiscard]] std::shared_ptr<TProcessInfo> GetProcessByKey(const ProcessOrThreadKey& key) const {
			auto it = m_processesByKey.find(key);
			return it == m_processesByKey.end() ? nullptr : it->second;
		}

		std::vector<std::shared_ptr<TThreadInfo>> const& GetThreads() const {
			return m_Threads;
		}

		[[nodiscard]] size_t GetProcessCount() const {
			return m_Processes.size();
		}

		[[nodiscard]] std::shared_ptr<TThreadInfo> GetThreadInfo(int index) const {
			return m_Threads[index];
		}

		[[nodiscard]] std::shared_ptr<TThreadInfo> GetThreadByKey(const ProcessOrThreadKey& key) const {
			auto it = m_threadsByKey.find(key);
			return it == m_threadsByKey.end() ? nullptr : it->second;
		}

		[[nodiscard]] const std::vector<std::shared_ptr<TThreadInfo>>& GetTerminatedThreads() const {
			return m_TerminatedThreads;
		}

		[[nodiscard]] const std::vector<std::shared_ptr<TThreadInfo>>& GetNewThreads() const {
			return m_NewThreads;
		}

		[[nodiscard]] size_t GetThreadCount() const {
			return m_Threads.size();
		}

		[[nodiscard]] std::vector<std::pair<std::shared_ptr<TProcessInfo>, int>> BuildProcessTree() {
			std::vector<std::pair<std::shared_ptr<TProcessInfo>, int>> tree;
			auto count = EnumProcesses(false, 0);
			tree.reserve(count);

			auto map = m_ProcessesById;
			for (auto& p : m_Processes) {
				auto it = m_ProcessesById.find(p->ParentId);
				if (p->ParentId == 0 || it == m_ProcessesById.end() || (it != m_ProcessesById.end() && it->second->CreateTime > p->CreateTime)) {
					// root
					DbgPrint((PSTR)"Root: %ws (%u) (Parent: %u)\n", p->GetImageName().c_str(), p->Id, p->ParentId);
					tree.push_back(std::make_pair(p, 0));
					map.erase(p->Id);
					if (p->Id == 0)
						continue;
					auto children = FindChildren(map, p.get(), 1);
					for (auto& child : children)
						tree.push_back(std::make_pair(m_ProcessesById[child.first], child.second));
				}
			}
			return tree;
		}

		std::vector<std::pair<uint32_t, int>> FindChildren(std::unordered_map<uint32_t, std::shared_ptr<TProcessInfo>>& map, TProcessInfo* parent, int indent) {
			std::vector<std::pair<uint32_t, int>> children;
			for (auto& p : m_Processes) {
				if (p->ParentId == parent->Id && p->CreateTime > parent->CreateTime) {
					children.push_back(std::make_pair(p->Id, indent));
					map.erase(p->Id);
					auto children2 = FindChildren(map, p.get(), indent + 1);
					children.insert(children.end(), children2.begin(), children2.end());
				}
			}
			return children;
		}

		private:
			using ProcessMap = std::unordered_map<ProcessOrThreadKey, std::shared_ptr<TProcessInfo>>;
			using ThreadMap = std::unordered_map<ProcessOrThreadKey, std::shared_ptr<TThreadInfo>>;

			std::shared_ptr<TProcessInfo> BuildProcessInfo(const SYSTEM_PROCESS_INFORMATION* info, bool includeThreads,
				ThreadMap& threadsByKey, int64_t delta, std::shared_ptr<TProcessInfo> pi, bool extended) {
				if (pi == nullptr) {
					pi = std::make_shared<TProcessInfo>();
					pi->NativeInfo = info;
					pi->Id = HandleToULong(info->UniqueProcessId);
					pi->Key.Created = info->CreateTime.QuadPart;
					pi->Key.Id = pi->Id;
					pi->ParentId = HandleToULong(info->InheritedFromUniqueProcessId);
					pi->ClearThreads();
					auto name = info->UniqueProcessId == 0 ? L"(Idle)" : std::wstring(info->ImageName.Buffer, info->ImageName.Length / sizeof(WCHAR));
					if (extended && info->UniqueProcessId) {
						auto ext = (SYSTEM_PROCESS_INFORMATION_EXTENSION*)((BYTE*)info +
							FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads) + sizeof(SYSTEM_EXTENDED_THREAD_INFORMATION) * info->NumberOfThreads);
						pi->ExtendedInfo = ext;
						auto index = name.rfind(L'\\');
						pi->m_ProcessName = index == std::wstring::npos ? name : name.substr(index + 1);
						pi->m_NativeImagePath = name;
						if (ext->PackageFullNameOffset > 0) {
							pi->m_PackageFullName = (const wchar_t*)((BYTE*)ext + ext->PackageFullNameOffset);
						}
					}
					else {
						pi->ExtendedInfo = nullptr;
						pi->m_ProcessName = name;
					}
				}

				if (includeThreads && pi->Id > 0) {
					auto threadCount = info->NumberOfThreads;
					for (ULONG i = 0; i < threadCount; i++) {
						auto tinfo = (SYSTEM_EXTENDED_THREAD_INFORMATION*)info->Threads + i;
						const auto& baseInfo = tinfo->ThreadInfo;
						ProcessOrThreadKey key = { baseInfo.CreateTime.QuadPart, HandleToULong(baseInfo.ClientId.UniqueThread) };
						std::shared_ptr<TThreadInfo> thread;
						std::shared_ptr<TThreadInfo> ti2;
						bool newobject = true;
						int64_t cpuTime;
						if (auto it = m_threadsByKey.find(key); it != m_threadsByKey.end()) {
							thread = it->second;
							cpuTime = thread->NativeInfo->UserTime.QuadPart + thread->NativeInfo->KernelTime.QuadPart;
							newobject = false;
						}
						if (newobject) {
							thread = std::make_shared<TThreadInfo>();
							thread->m_ProcessName = pi->GetImageName();
							thread->Id = HandleToULong(baseInfo.ClientId.UniqueThread);
							thread->ProcessId = HandleToULong(baseInfo.ClientId.UniqueProcess);
							thread->NativeInfo = &tinfo->ThreadInfo;
							thread->ExtendedInfo = tinfo;
							thread->Key = key;
						}

						pi->AddThread(thread);

						m_Threads.push_back(thread);
						if (newobject) {
							// new thread
							thread->CPU = 0;
							m_NewThreads.push_back(thread);
						}
						else {
							thread->CPU = delta == 0 ? 0 : (int32_t)((thread->NativeInfo->KernelTime.QuadPart + thread->NativeInfo->UserTime.QuadPart - cpuTime) * 1000000LL / delta / 1/*_totalProcessors*/);
							m_threadsByKey.erase(thread->Key);
						}
						threadsByKey.insert({ thread->Key, thread });
						m_ThreadsById.insert({ thread->Id, thread });
					}
				}
				return pi;
			}

			// processes

			std::unordered_map<uint32_t, std::shared_ptr<TProcessInfo>> m_ProcessesById;
			std::vector<std::shared_ptr<TProcessInfo>> m_Processes;
			std::vector<std::shared_ptr<TProcessInfo>> m_TerminatedProcesses;
			std::vector<std::shared_ptr<TProcessInfo>> m_NewProcesses;
			ProcessMap m_processesByKey;

			// threads

			std::vector<std::shared_ptr<TThreadInfo>> m_Threads;
			std::vector<std::shared_ptr<TThreadInfo>> m_NewThreads;
			std::vector<std::shared_ptr<TThreadInfo>> m_TerminatedThreads;
			std::unordered_map<uint32_t, std::shared_ptr<TThreadInfo>> m_ThreadsById;
			ThreadMap m_threadsByKey;

			LARGE_INTEGER m_PrevTicks{};
			inline static uint32_t s_TotalProcessors;
			inline static bool s_IsElevated;

			wil::unique_virtualalloc_ptr<BYTE> m_Buffer;
	};
}


