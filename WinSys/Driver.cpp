#include "pch.h"
#include "Driver.h"
#include "..\KWinSys\KWinSysPublic.h"

using namespace WinSys;

bool Driver::Open() {
    m_hDevice.reset(::CreateFile(KWINSYS_DEVNAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    return m_hDevice.is_valid();
}

bool Driver::IsOpen() const {
    return m_hDevice.is_valid();
}

HANDLE Driver::DuplicateHandle(DWORD pid, HANDLE handle, ACCESS_MASK access, DWORD flags) const {
    DupHandleData data;
    data.SourcePid = pid;
    data.SourceHandle = PtrToLong(handle);
    data.AccessMask = access;
    data.Flags = flags;
    HANDLE hObject{ nullptr };
    DWORD bytes;
    ::DeviceIoControl(m_hDevice.get(), IOCTL_WINSYS_DUP_HANDLE,
        &data, sizeof(data), &hObject, sizeof(hObject), &bytes, nullptr);
    return hObject;
}

HANDLE Driver::OpenProcess(ACCESS_MASK access, DWORD pid) const {
    return OpenProcessThreadCommon(IOCTL_WINSYS_OPEN_PROCESS, access, pid);
}

HANDLE Driver::OpenThread(ACCESS_MASK access, DWORD pid) const {
    return OpenProcessThreadCommon(IOCTL_WINSYS_OPEN_THREAD, access, pid);
}

HANDLE Driver::OpenObjectByName(ACCESS_MASK access, PCWSTR name, USHORT typeIndex) const {
    auto len = (ULONG)wcslen(name);
    ULONG size = len * sizeof(WCHAR) + sizeof(OpenObjectByNameData);
    auto buffer = std::make_unique<BYTE[]>(size);
    if (!buffer)
        return nullptr;

    auto data = reinterpret_cast<OpenObjectByNameData*>(buffer.get());
    data->Access = access;
    data->TypeIndex = typeIndex;
    wcscpy_s(data->Name, len + 1, name);
    HANDLE hObject{ nullptr };
    DWORD bytes;
    ::DeviceIoControl(m_hDevice.get(), IOCTL_WINSYS_OPEN_OBJECT_BY_NAME,
        data, size, &hObject, sizeof(hObject), &bytes, nullptr);
    return hObject;
}

DWORD WinSys::Driver::GetVersion() const {
    DWORD version = 0;
    DWORD bytes;
    ::DeviceIoControl(m_hDevice.get(), IOCTL_WINSYS_GET_VERSION, nullptr, 0, &version, sizeof(version), &bytes, nullptr);
    return version;
}

HANDLE Driver::OpenProcessThreadCommon(DWORD ioctl, ACCESS_MASK access, DWORD id) const {
    OpenProcessThreadData data;
    data.AccessMask = access;
    data.Id = id;
    HANDLE hProcess;
    DWORD bytes;
    return ::DeviceIoControl(m_hDevice.get(), ioctl, &data, sizeof(data), &hProcess, sizeof(hProcess), &bytes, nullptr) ? hProcess : nullptr;
}
