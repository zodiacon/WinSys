#pragma once

#define DRIVER_CURRENT_VERSION 0x0100
#define DRIVER_PREFIX "KWinSys: "
#define DEVICE_NAME L"\\Device\\KWinSys"
#define DRIVER_TAG 'sysw'

extern "C" NTSTATUS ZwOpenThread(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId);

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
);

extern "C" NTSTATUS ObOpenObjectByName(
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Inout_opt_ PACCESS_STATE AccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_Inout_opt_ PVOID ParseContext,
	_Out_ PHANDLE Handle);

namespace NT {
	typedef struct _OBJECT_TYPE_INFORMATION {
		UNICODE_STRING TypeName;
		ULONG TotalNumberOfObjects;
		ULONG TotalNumberOfHandles;
		ULONG TotalPagedPoolUsage;
		ULONG TotalNonPagedPoolUsage;
		ULONG TotalNamePoolUsage;
		ULONG TotalHandleTableUsage;
		ULONG HighWaterNumberOfObjects;
		ULONG HighWaterNumberOfHandles;
		ULONG HighWaterPagedPoolUsage;
		ULONG HighWaterNonPagedPoolUsage;
		ULONG HighWaterNamePoolUsage;
		ULONG HighWaterHandleTableUsage;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccessMask;
		BOOLEAN SecurityRequired;
		BOOLEAN MaintainHandleCount;
		UCHAR TypeIndex; // since WINBLUE
		CHAR ReservedByte;
		ULONG PoolType;
		ULONG DefaultPagedPoolCharge;
		ULONG DefaultNonPagedPoolCharge;
	} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

	enum class ObjectInformationClass {
		BasicInformation, // OBJECT_BASIC_INFORMATION
		NameInformation, // OBJECT_NAME_INFORMATION
		TypeInformation, // OBJECT_TYPE_INFORMATION
		TypesInformation, // OBJECT_TYPES_INFORMATION
		HandleFlagInformation, // OBJECT_HANDLE_FLAG_INFORMATION
		SessionInformation,
		SessionObjectInformation,
	} OBJECT_INFORMATION_CLASS;
	
	typedef struct _OBJECT_TYPES_INFORMATION {
		ULONG NumberOfTypes;
		OBJECT_TYPE_INFORMATION TypeInformation[1];
	} OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
