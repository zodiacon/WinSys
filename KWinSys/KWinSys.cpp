#include "pch.h"
#include "KWinSysPublic.h"
#include "KWinSys.h"

NTSTATUS InitGlobals();
void WinSysUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS WinSysCreateClose(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS WinSysDeviceControl(PDEVICE_OBJECT, PIRP Irp);

extern "C" POBJECT_TYPE* IoDeviceObjectType;
extern "C" POBJECT_TYPE* LpcPortObjectType;
extern "C" POBJECT_TYPE* IoDriverObjectType;
extern "C" POBJECT_TYPE* ExWindowStationObjectType;
extern "C" POBJECT_TYPE* MmSectionObjectType;
extern "C" POBJECT_TYPE* ExTimerObjectType;

POBJECT_TYPE g_ObjectTypes[256];
ULONG g_NumberOfTypes;

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	PDEVICE_OBJECT devObj;
	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
	auto status = IoCreateDeviceSecure(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, 
		&SDDL_DEVOBJ_SYS_ALL_ADM_ALL, nullptr, &devObj);
	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to create device object (0x%X)\n", status));
		return status;
	}

	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\KWinSys");
	status = IoCreateSymbolicLink(&symName, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(devObj);
		KdPrint((DRIVER_PREFIX "Failed to create symbolic link (0x%X)\n", status));
		return status;
	}

	DriverObject->DriverUnload = WinSysUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = WinSysCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WinSysDeviceControl;

	status = InitGlobals();
	if (!NT_SUCCESS(status)) {
		DbgPrint(DRIVER_PREFIX "Warning: Failed to init globals (0x%X)\n", status);
	}
	return STATUS_SUCCESS;
}

NTSTATUS InitGlobals() {
	ULONG size = 1 << 14;
	auto types = (NT::POBJECT_TYPES_INFORMATION)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
	if (!types)
		return STATUS_NO_MEMORY;

	auto status = ZwQueryObject(nullptr, (OBJECT_INFORMATION_CLASS)NT::ObjectInformationClass::TypesInformation, types, size, nullptr);

	if (NT_SUCCESS(status)) {
		const struct {
			PCWSTR Name;
			POBJECT_TYPE Type;
			PVOID Function;
		} objectTypes[] = {
			{ L"Process", *PsProcessType },
			{ L"Thread", *PsThreadType },
			{ L"Job", *PsJobType },
			{ L"Event", *ExEventObjectType },
			{ L"Semaphore", *ExSemaphoreObjectType },
			{ L"File", *IoFileObjectType },
			{ L"Key", *CmKeyObjectType },
			{ L"Token", *SeTokenObjectType },
			{ L"Device", *IoDeviceObjectType },
			{ L"Driver", *IoDriverObjectType },
			{ L"Section", *MmSectionObjectType },
			{ L"Desktop", *ExDesktopObjectType },
			{ L"WindowStation", *ExWindowStationObjectType },
			{ L"ALPC Port", *LpcPortObjectType },
			{ L"Timer", *ExTimerObjectType },
			{ L"Session", POBJECT_TYPE(ObjectType::Session) },
			{ L"SymbolicLink", POBJECT_TYPE(ObjectType::SymbolicLink) },
		};

		g_NumberOfTypes = types->NumberOfTypes;
		auto type = &types->TypeInformation[0];
		for (ULONG i = 0; i < types->NumberOfTypes; i++) {
			for (auto& ot : objectTypes) {
				if (_wcsnicmp(ot.Name, type->TypeName.Buffer, wcslen(ot.Name)) == 0) {
					g_ObjectTypes[type->TypeIndex] = ot.Type;
					break;
				}
			}
			auto temp = (PUCHAR)type + sizeof(NT::OBJECT_TYPE_INFORMATION) + type->TypeName.MaximumLength;
			temp += sizeof(PVOID) - 1;
			type = reinterpret_cast<NT::OBJECT_TYPE_INFORMATION*>((ULONG_PTR)temp / sizeof(PVOID) * sizeof(PVOID));
		}
	}

	ExFreePool(types);
	return status;
}

void WinSysUnload(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\KWinSys");
	IoDeleteSymbolicLink(&symName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS WinSysCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	return CompleteRequest(Irp);
}

NTSTATUS WinSysDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	const auto& dic = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl;
	auto status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG len = 0;
	auto sysBuffer = Irp->AssociatedIrp.SystemBuffer;

	switch (dic.IoControlCode) {
		case IOCTL_WINSYS_GET_VERSION:
			if (sysBuffer == nullptr || dic.OutputBufferLength < sizeof(ULONG)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			*(ULONG*)sysBuffer = KWINSYS_VERSION;
			len = sizeof(ULONG);
			status = STATUS_SUCCESS;
			break;

		case IOCTL_WINSYS_OPEN_OBJECT_BY_NAME:
			if (g_ObjectTypes == nullptr) {
				status = STATUS_NOT_SUPPORTED;
				break;
			}
			if (sysBuffer == nullptr || dic.OutputBufferLength < sizeof(HANDLE) || 
				dic.InputBufferLength < sizeof(OpenObjectByNameData) ||	dic.InputBufferLength > 2048) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			auto data = (OpenObjectByNameData*)sysBuffer;
			if (data->TypeIndex > 255) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			//
			// make sure name is NULL-terminated
			//
			*(WCHAR*)((PUCHAR)sysBuffer + dic.InputBufferLength - sizeof(WCHAR)) = 0;
			UNICODE_STRING name;
			RtlInitUnicodeString(&name, data->Name);
			OBJECT_ATTRIBUTES objAttr = RTL_INIT_OBJECT_ATTRIBUTES(&name, 0);
			HANDLE hObject{ nullptr };
			if (g_ObjectTypes[data->TypeIndex]) {
				if (ULONG_PTR(g_ObjectTypes[data->TypeIndex]) > 0x10000) {
					status = ObOpenObjectByName(&objAttr, g_ObjectTypes[data->TypeIndex], KernelMode, nullptr, data->Access, nullptr, &hObject);
				}
				else {
					//
					// must handle special cases, where the object type is not exported
					//
					switch (ObjectType(ULONG_PTR(g_ObjectTypes[data->TypeIndex]))) {
						case ObjectType::Session:
							status = ZwOpenSession(&hObject, data->Access, &objAttr);
							break;

						case ObjectType::SymbolicLink:
							status = ZwOpenSymbolicLinkObject(&hObject, data->Access, &objAttr);
							break;
					}
				}
			}
			if (NT_SUCCESS(status)) {
				*(PHANDLE)sysBuffer = hObject;
				len = sizeof(HANDLE);
			}
			break;
	}
	return CompleteRequest(Irp, status, len);
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}
