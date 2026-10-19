#pragma once

#include <optional>
#include <string>
#include <vector>

// Requires the phnt headers (included by pch.h) for the native structure definitions.

namespace WinSys {
	//
	// Static wrappers around NtQuerySystemInformation(Ex), one per queryable SYSTEM_INFORMATION_CLASS.
	// Naming: SystemXxx maps to GetXxx.
	// Fixed-size results are returned as std::optional<native struct>; strings as std::wstring/std::string;
	// arrays as std::vector<> (empty on failure). GetLastStatus() returns the NTSTATUS of the last call on this thread.
	// In the result types below, the native structure is kept as "Info", with its string/pointer-to-buffer members
	// cleared; use the converted C++ members instead.
	//
	struct SystemInfo final {
		struct Process {
			SYSTEM_PROCESS_INFORMATION Info{};	// ImageName cleared, Threads not valid
			std::wstring ImageName;
			// For SystemProcessInformation/SystemSessionProcessInformation only ThreadInfo is filled
			std::vector<SYSTEM_EXTENDED_THREAD_INFORMATION> Threads;
			// SystemFullProcessInformation only
			std::optional<SYSTEM_PROCESS_INFORMATION_EXTENSION> Extension;
			std::wstring PackageFullName;
			std::wstring AppId;
			std::wstring UserSid;
		};

		struct Module {
			RTL_PROCESS_MODULE_INFORMATION Info{};
			std::string FullPath;
			std::string FileName;
		};

		struct ModuleEx {
			RTL_PROCESS_MODULE_INFORMATION_EX Info{};
			std::string FullPath;
			std::string FileName;
		};

		struct BackTrace {
			ULONG TraceCount;
			USHORT Index;
			std::vector<void*> Frames;
		};

		struct StackTraceInformation {
			ULONG CommittedMemory;
			ULONG ReservedMemory;
			ULONG NumberOfBackTraceLookups;
			std::vector<BackTrace> BackTraces;
		};

		struct Object {
			SYSTEM_OBJECT_INFORMATION Info{};	// NameInfo cleared
			std::wstring Name;
		};

		struct ObjectType {
			SYSTEM_OBJECTTYPE_INFORMATION Info{};	// TypeName cleared
			std::wstring TypeName;
			std::vector<Object> Objects;
		};

		struct PageFile {
			SYSTEM_PAGEFILE_INFORMATION_EX Info{};	// PageFileName cleared; MinimumSize/MaximumSize set by the Ex query only
			std::wstring Name;
		};

		struct LegacyDriverInformation {
			SYSTEM_LEGACY_DRIVER_INFORMATION Info{};
			std::wstring VetoList;
		};

		struct TimeZone {
			RTL_TIME_ZONE_INFORMATION Info{};
			std::wstring StandardName;
			std::wstring DaylightName;
		};

		struct DynamicTimeZone {
			DYNAMIC_TIME_ZONE_INFORMATION Info{};
			std::wstring StandardName;
			std::wstring DaylightName;
			std::wstring TimeZoneKeyName;
		};

		struct Verifier {
			SYSTEM_VERIFIER_INFORMATION Info{};
			std::wstring DriverName;
		};

		struct VerifierEx {
			SYSTEM_VERIFIER_INFORMATION_EX Info{};
			std::wstring PreviousBucketName;
		};

		struct SessionPoolTags {
			ULONG SessionId;
			std::vector<SYSTEM_POOLTAG> Tags;
		};

		struct RefTrace {
			SYSTEM_REF_TRACE_INFORMATION Info{};
			std::wstring TraceProcessName;
			std::wstring TracePoolTags;
		};

		struct ProcessorPerformanceStates {
			ULONG ProcessorNumber;
			std::vector<SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT> States;
		};

		// Flattened SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX; only the members matching Relationship are set
		struct LogicalProcessorRelationship {
			LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
			// RelationProcessorCore, RelationProcessorPackage, RelationProcessorDie, RelationProcessorModule
			BYTE Flags{};
			BYTE EfficiencyClass{};
			// RelationNumaNode, RelationNumaNodeEx
			DWORD NodeNumber{};
			// RelationCache
			BYTE CacheLevel{};
			BYTE Associativity{};
			WORD LineSize{};
			DWORD CacheSize{};
			PROCESSOR_CACHE_TYPE CacheType{};
			// processor, NUMA and cache relationships
			std::vector<GROUP_AFFINITY> GroupMasks;
			// RelationGroup
			WORD MaximumGroupCount{};
			std::vector<PROCESSOR_GROUP_INFO> Groups;
		};

		struct VhdBootInformation {
			SYSTEM_VHD_BOOT_INFORMATION Info{};
			std::wstring OsVhdParentVolume;
		};

		struct MemoryTopology {
			ULONG NumberOfNodes;
			ULONG NumberOfChannels;
			std::vector<PHYSICAL_CHANNEL_RUN> Runs;
		};

		struct BootLogo {
			ULONG Flags;
			std::vector<BYTE> Bitmap;
		};

		struct CriticalProcessErrorLog {
			CRITICAL_PROCESS_EXCEPTION_DATA Info{};
			std::wstring ModuleName;
		};

		struct ManufacturingInformation {
			SYSTEM_MANUFACTURING_INFORMATION Info{};
			std::wstring ProfileName;
		};

		struct SecureBootPolicyFull {
			SYSTEM_SECUREBOOT_POLICY_INFORMATION PolicyInformation;
			std::vector<BYTE> Policy;
		};

		struct CpuSetList {
			ULONGLONG Id;	// Tag or WorkloadClass
			std::vector<ULONGLONG> CpuSets;
		};

		struct BuildVersion {
			SYSTEM_BUILD_VERSION_INFORMATION Info{};
			std::string LayerName;
			std::string NtBuildBranch;
			std::string NtBuildLab;
			std::string NtBuildLabEx;
			std::string NtBuildStamp;
			std::string NtBuildArch;
		};

		static NTSTATUS GetLastStatus() noexcept;

		static std::optional<SYSTEM_BASIC_INFORMATION> GetBasicInformation();
		static std::optional<SYSTEM_PROCESSOR_INFORMATION> GetProcessorInformation();
		static std::optional<SYSTEM_PERFORMANCE_INFORMATION> GetPerformanceInformation();
		static std::optional<SYSTEM_TIMEOFDAY_INFORMATION> GetTimeOfDayInformation();
		static std::vector<Process> GetProcessInformation();
		// Raw ULONGs following the SYSTEM_CALL_COUNT_INFORMATION header (checked kernels only)
		static std::vector<ULONG> GetCallCountInformation();
		static std::optional<SYSTEM_DEVICE_INFORMATION> GetDeviceInformation();
		static std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> GetProcessorPerformanceInformation(std::optional<USHORT> group = {});
		static std::optional<SYSTEM_FLAGS_INFORMATION> GetFlagsInformation();
		// SystemModuleInformation (named to avoid the psapi GetModuleInformation macro)
		static std::vector<Module> GetKernelModuleInformation();
		static std::vector<RTL_PROCESS_LOCK_INFORMATION> GetLocksInformation();
		static std::optional<StackTraceInformation> GetStackTraceInformation();
		static std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> GetHandleInformation();
		// Requires the FLG_MAINTAIN_OBJECT_TYPELIST global flag
		static std::vector<ObjectType> GetObjectInformation();
		static std::vector<PageFile> GetPageFileInformation();
		static std::optional<SYSTEM_VDM_INSTEMUL_INFO> GetVdmInstemulInformation();
		static std::optional<SYSTEM_FILECACHE_INFORMATION> GetFileCacheInformation();
		static std::vector<SYSTEM_POOLTAG> GetPoolTagInformation();
		static std::vector<SYSTEM_INTERRUPT_INFORMATION> GetInterruptInformation(std::optional<USHORT> group = {});
		static std::optional<SYSTEM_DPC_BEHAVIOR_INFORMATION> GetDpcBehaviorInformation();
		static std::optional<SYSTEM_QUERY_TIME_ADJUST_INFORMATION> GetTimeAdjustmentInformation();
		// SystemExceptionInformation (named to avoid the GetExceptionInformation intrinsic macro)
		static std::optional<SYSTEM_EXCEPTION_INFORMATION> GetSystemExceptionInformation();
		static std::optional<SYSTEM_KERNEL_DEBUGGER_INFORMATION> GetKernelDebuggerInformation();
		static std::optional<SYSTEM_CONTEXT_SWITCH_INFORMATION> GetContextSwitchInformation();
		static std::optional<SYSTEM_REGISTRY_QUOTA_INFORMATION> GetRegistryQuotaInformation();
		static std::vector<SYSTEM_PROCESSOR_IDLE_INFORMATION> GetProcessorIdleInformation(std::optional<USHORT> group = {});
		static std::optional<LegacyDriverInformation> GetLegacyDriverInformation();
		static std::optional<TimeZone> GetCurrentTimeZoneInformation();
		static std::vector<SYSTEM_LOOKASIDE_INFORMATION> GetLookasideInformation();
		static std::optional<SYSTEM_RANGE_START_INFORMATION> GetRangeStartInformation();
		static std::vector<Verifier> GetVerifierInformation();
		static std::vector<Process> GetSessionProcessInformation(ULONG sessionId);
		static std::optional<SYSTEM_NUMA_INFORMATION> GetNumaProcessorMap();
		static std::vector<Process> GetExtendedProcessInformation();
		static std::optional<ULONG> GetRecommendedSharedDataAlignment();
		static std::optional<ULONG> GetComPlusPackage();
		static std::optional<SYSTEM_NUMA_INFORMATION> GetNumaAvailableMemory();
		static std::vector<SYSTEM_PROCESSOR_POWER_INFORMATION> GetProcessorPowerInformation(std::optional<USHORT> group = {});
		static std::optional<SYSTEM_BASIC_INFORMATION> GetEmulationBasicInformation();
		static std::optional<SYSTEM_PROCESSOR_INFORMATION> GetEmulationProcessorInformation();
		static std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> GetExtendedHandleInformation();
		static std::optional<ULONG> GetLostDelayedWriteInformation();
		static std::vector<SYSTEM_BIGPOOL_ENTRY> GetBigPoolInformation();
		static std::vector<SessionPoolTags> GetSessionPoolTagInformation();
		static std::vector<SYSTEM_SESSION_MAPPED_VIEW_INFORMATION> GetSessionMappedViewInformation();
		static std::optional<ULONG> GetObjectSecurityMode();
		static std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> GetLogicalProcessorInformation(std::optional<USHORT> group = {});
		// Returns the table (Get) or the list of table IDs (Enumerate) for the given provider ('RSMB', 'ACPI', 'FIRM')
		static std::vector<BYTE> GetFirmwareTableInformation(ULONG providerSignature, SYSTEM_FIRMWARE_TABLE_ACTION action, ULONG tableId = 0);
		static std::vector<ModuleEx> GetKernelModuleInformationEx();
		static std::optional<SYSTEM_MEMORY_LIST_INFORMATION> GetMemoryListInformation();
		static std::optional<SYSTEM_FILECACHE_INFORMATION> GetFileCacheInformationEx();
		static std::vector<SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION> GetProcessorIdleCycleTimeInformation(std::optional<USHORT> group = {});
		static std::optional<SYSTEM_VERIFIER_CANCELLATION_INFORMATION> GetVerifierCancellationInformation();
		static std::optional<RefTrace> GetRefTraceInformation();
		static std::optional<SYSTEM_SPECIAL_POOL_INFORMATION> GetSpecialPoolInformation();
		// Full native image path of any process, without opening it
		static std::wstring GetProcessIdInformation(ULONG pid);
		static std::optional<SYSTEM_BOOT_ENVIRONMENT_INFORMATION> GetBootEnvironmentInformation();
		static std::optional<SYSTEM_HYPERVISOR_QUERY_INFORMATION> GetHypervisorInformation();
		static std::optional<VerifierEx> GetVerifierInformationEx();
		static std::optional<TimeZone> GetTimeZoneInformation();
		static std::optional<SYSTEM_PREFETCH_PATCH_INFORMATION> GetPrefetchPatchInformation();
		static std::wstring GetSystemPartitionInformation();
		static std::wstring GetSystemDiskInformation();
		static std::vector<ProcessorPerformanceStates> GetProcessorPerformanceDistribution(std::optional<USHORT> group = {});
		// Returns the node number for the proximity ID
		static std::optional<USHORT> GetNumaProximityNodeInformation(ULONG nodeProximityId);
		static std::optional<DynamicTimeZone> GetDynamicTimeZoneInformation();
		static std::optional<SYSTEM_CODEINTEGRITY_INFORMATION> GetCodeIntegrityInformation();
		static std::string GetProcessorBrandString();
		static std::vector<SYSTEM_VA_LIST_INFORMATION> GetVirtualAddressInformation();
		static std::vector<LogicalProcessorRelationship> GetLogicalProcessorAndGroupInformation(LOGICAL_PROCESSOR_RELATIONSHIP relationship = RelationAll);
		static std::vector<SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION> GetProcessorCycleTimeInformation(std::optional<USHORT> group = {});
		static std::optional<VhdBootInformation> GetVhdBootInformation();
		static std::vector<PS_CPU_QUOTA_QUERY_ENTRY> GetCpuQuotaInformation();
		static std::optional<SYSTEM_BASIC_INFORMATION> GetNativeBasicInformation();
		static std::optional<SYSTEM_ERROR_PORT_TIMEOUTS> GetErrorPortTimeouts();
		static std::optional<SYSTEM_LOW_PRIORITY_IO_INFORMATION> GetLowPriorityIoInformation();
		static std::optional<BOOT_ENTROPY_NT_RESULT> GetTpmBootEntropyInformation();
		static std::optional<SYSTEM_VERIFIER_COUNTERS_INFORMATION> GetVerifierCountersInformation();
		static std::optional<SYSTEM_FILECACHE_INFORMATION> GetPagedPoolInformationEx();
		static std::optional<SYSTEM_FILECACHE_INFORMATION> GetSystemPtesInformationEx();
		static std::vector<USHORT> GetNodeDistanceInformation(USHORT node);
		static std::optional<SYSTEM_ACPI_AUDIT_INFORMATION> GetAcpiAuditInformation();
		static std::optional<SYSTEM_BASIC_PERFORMANCE_INFORMATION> GetBasicPerformanceInformation();
		static std::optional<SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION> GetQueryPerformanceCounterInformation();
		static std::vector<SessionPoolTags> GetSessionBigPoolInformation();
		static std::vector<SYSTEM_BAD_PAGE_INFORMATION> GetBadPageInformation();
		static std::optional<SYSTEM_CONSOLE_INFORMATION> GetConsoleInformation();
		static std::optional<SYSTEM_PLATFORM_BINARY_INFORMATION> GetPlatformBinaryInformation();
		static std::optional<SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION> GetHypervisorProcessorCountInformation();
		static std::optional<MemoryTopology> GetMemoryTopologyInformation();
		static std::optional<SYSTEM_MEMORY_CHANNEL_INFORMATION> GetMemoryChannelInformation(ULONG channel);
		static std::optional<BootLogo> GetBootLogoInformation();
		static std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX> GetProcessorPerformanceInformationEx(std::optional<USHORT> group = {});
		static std::optional<CriticalProcessErrorLog> GetCriticalProcessErrorLogInformation();
		static std::optional<SYSTEM_SECUREBOOT_POLICY_INFORMATION> GetSecureBootPolicyInformation();
		static std::vector<PageFile> GetPageFileInformationEx();
		static std::optional<SYSTEM_SECUREBOOT_INFORMATION> GetSecureBootInformation();
		static std::optional<SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION> GetPortableWorkspaceEfiLauncherInformation();
		// Requires admin
		static std::vector<Process> GetFullProcessInformation();
		static std::optional<SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX> GetKernelDebuggerInformationEx();
		static std::optional<ULONG> GetSoftRebootInformation();
		static std::optional<OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2> GetOfflineDumpConfigInformation();
		static std::optional<SYSTEM_PROCESSOR_FEATURES_INFORMATION> GetProcessorFeaturesInformation();
		static std::vector<BYTE> GetEdidInformation();
		static std::optional<ManufacturingInformation> GetManufacturingInformation();
		static std::optional<SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION> GetEnergyEstimationConfigInformation();
		static std::optional<SYSTEM_HYPERVISOR_DETAIL_INFORMATION> GetHypervisorDetailInformation();
		static std::vector<SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION> GetProcessorCycleStatsInformation(USHORT group);
		static std::optional<SYSTEM_TPM_INFORMATION> GetTrustedPlatformModuleInformation();
		static std::optional<SYSTEM_KERNEL_DEBUGGER_FLAGS> GetKernelDebuggerFlags();
		static std::optional<SYSTEM_CODEINTEGRITYPOLICY_INFORMATION> GetCodeIntegrityPolicyInformation();
		static std::optional<SYSTEM_ISOLATED_USER_MODE_INFORMATION> GetIsolatedUserModeInformation();
		// The kernel module containing the given address
		static std::optional<ModuleEx> GetSingleModuleInformation(void* address);
		static std::optional<SYSTEM_VSM_PROTECTION_INFORMATION> GetVsmProtectionInformation();
		static std::optional<SecureBootPolicyFull> GetSecureBootPolicyFullInformation();
		// KAFFINITY_EX bitmap
		static std::vector<ULONG_PTR> GetAffinitizedInterruptProcessorInformation();
		static std::vector<ULONG> GetRootSiloInformation();
		static std::vector<SYSTEM_CPU_SET_INFORMATION> GetCpuSetInformation(HANDLE hProcess = nullptr);
		static std::optional<CpuSetList> GetCpuSetTagInformation();
		static std::optional<SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION> GetSecureKernelProfileInformation();
		static std::vector<BYTE> GetCodeIntegrityPlatformManifestInformation();
		static std::optional<SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT> GetInterruptSteeringInformation(SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT const& input);
		static std::vector<SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION> GetSupportedProcessorArchitectures(HANDLE hProcess = nullptr);
		static std::optional<SYSTEM_MEMORY_USAGE_INFORMATION> GetMemoryUsageInformation();
		static std::optional<SYSTEM_PHYSICAL_MEMORY_INFORMATION> GetPhysicalMemoryInformation();
		static std::optional<SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION> GetCodeIntegrityUnlockInformation();
		static std::optional<SYSTEM_FLUSH_INFORMATION> GetFlushInformation();
		static std::vector<ULONG_PTR> GetProcessorIdleMaskInformation();
		static std::optional<SYSTEM_WRITE_CONSTRAINT_INFORMATION> GetWriteConstraintInformation();
		static std::optional<SYSTEM_KERNEL_VA_SHADOW_INFORMATION> GetKernelVaShadowInformation();
		static std::optional<SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION> GetHypervisorSharedPageInformation();
		static std::wstring GetFirmwarePartitionInformation();
		static std::optional<SYSTEM_SPECULATION_CONTROL_INFORMATION> GetSpeculationControlInformation();
		static std::optional<SYSTEM_DMA_GUARD_POLICY_INFORMATION> GetDmaGuardPolicyInformation();
		static std::vector<BYTE> GetEnclaveLaunchControlInformation();
		static std::optional<CpuSetList> GetWorkloadAllowedCpuSetsInformation();
		static std::optional<SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION> GetCodeIntegrityUnlockModeInformation();
		static std::optional<SYSTEM_FLAGS_INFORMATION> GetFlags2Information();
		static std::optional<SYSTEM_SECURITY_MODEL_INFORMATION> GetSecurityModelInformation();
		static std::optional<SYSTEM_FEATURE_CONFIGURATION_INFORMATION> GetFeatureConfigurationInformation(RTL_FEATURE_ID featureId, RTL_FEATURE_CONFIGURATION_TYPE type = RtlFeatureConfigurationBoot);
		static std::optional<SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION> GetFeatureConfigurationSectionInformation();
		static std::vector<SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS> GetFeatureUsageSubscriptionInformation();
		static std::optional<SECURE_SPECULATION_CONTROL_INFORMATION> GetSecureSpeculationControlInformation();
		static std::optional<SYSTEM_FIRMWARE_RAMDISK_INFORMATION> GetFwRamdiskInformation();
		static std::optional<SYSTEM_SHADOW_STACK_INFORMATION> GetShadowStackInformation();
		static std::optional<BuildVersion> GetBuildVersionInformation(ULONG layer = 0);
		static std::vector<SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION> GetSupportedProcessorArchitectures2(HANDLE hProcess = nullptr);
		static std::vector<LogicalProcessorRelationship> GetSingleProcessorRelationshipInformation(PROCESSOR_NUMBER const& processor);
		static std::optional<SYSTEM_XFG_FAILURE_INFORMATION> GetXfgCheckFailureInformation();
		static std::optional<SYSTEM_IOMMU_STATE_INFORMATION> GetIommuStateInformation();
		static std::optional<SYSTEM_HYPERVISOR_MINROOT_INFORMATION> GetHypervisorMinrootInformation();
		static std::vector<ULONG_PTR> GetHypervisorBootPagesInformation();
		static std::optional<SYSTEM_POINTER_AUTH_INFORMATION> GetPointerAuthInformation();
		static std::optional<SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT> GetOriginalImageFeatureInformation(PCWSTR featureName, ULONG bornOnVersion);
		static std::optional<SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT> GetMemoryNumaInformation(ULONG targetNode);
		static std::vector<SYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY> GetMemoryNumaPerformanceInformation(ULONG targetNode, SYSTEM_MEMORY_NUMA_PERFORMANCE_QUERY_DATA_TYPES dataType);
		static std::optional<SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION> GetTrustedAppsRuntimeInformation();
		static std::vector<SYSTEM_BAD_PAGE_INFORMATION> GetBadPageInformationEx();
		static std::optional<ULONG> GetResourceDeadlockTimeout();
		static std::optional<ULONG> GetBreakOnContextUnwindFailureInformation();
		static std::vector<SYSTEM_OSL_RAMDISK_ENTRY> GetOslRamdiskInformation();
	};
}
