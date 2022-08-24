#include "pch.h"
#include "VirtualDiskService.h"

using namespace WinSys::Vds;

bool VirtualDiskService::Load(std::wstring_view computerName) {
	auto loader = wil::CoCreateInstanceNoThrow<IVdsServiceLoader>(CLSID_VdsLoader, CLSCTX_ALL);
	if (!loader)
		return false;

	return SUCCEEDED(loader->LoadService((PWSTR)computerName.data(), m_svc.addressof()));
}

bool VirtualDiskService::IsServiceReady() const {
	return m_svc->IsServiceReady() == S_OK;
}

bool VirtualDiskService::WaitForServiceReady() {
	return m_svc->WaitForServiceReady() == S_OK;
}

VdsServiceProperties VirtualDiskService::GetProperties() const {
	VDS_SERVICE_PROP props;
	if (FAILED(m_svc->GetProperties(&props)))
		return {};

	VdsServiceProperties vdsprops{ props.pwszVersion, (VdsServiceFlags)props.ulFlags };
	::CoTaskMemFree(props.pwszVersion);

	return vdsprops;
}

std::vector<VdsProvider> WinSys::Vds::VirtualDiskService::QueryProviders(VdsProviderMask mask) {
	std::vector<VdsProvider> providers;
	wil::com_ptr<IEnumVdsObject> spEnum;
	m_svc->QueryProviders((DWORD)mask, &spEnum);
	if (!spEnum)
		return providers;

	wil::com_ptr<IUnknown> spUnk;
	ULONG len;
	while (S_OK == spEnum->Next(1, &spUnk, &len)) {
		wil::com_ptr<IVdsProvider> spProvider;
		spUnk.query_to(&spProvider);
		assert(spProvider);
		providers.emplace_back(spProvider.get());
	}
	return providers;
}

bool VirtualDiskService::Reenumerate() {
	return SUCCEEDED(m_svc->Reenumerate());
}

bool VirtualDiskService::Refresh() {
	return SUCCEEDED(m_svc->Refresh());
}