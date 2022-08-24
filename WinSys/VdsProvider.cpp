#include "pch.h"
#include "VdsProvider.h"

using namespace WinSys::Vds;

WinSys::Vds::VdsProvider::VdsProvider(IVdsProvider* provider) : m_provider(provider) {
}

std::optional<VdsProviderProperties> VdsProvider::GetProperties() const {
    VDS_PROVIDER_PROP properties;
    if (FAILED(m_provider->GetProperties(&properties)))
        return {};

    VdsProviderProperties props;
    props.Flags = (VdsProviderFlags)properties.ulFlags;
    props.Id = properties.id;
    props.VersionId = properties.guidVersionId;
    props.Version = properties.pwszVersion;
    props.Name = properties.pwszName;
    props.StripSizeBits = properties.ulStripeSizeFlags;
    props.RebuildPriority = properties.sRebuildPriority;
    if (properties.pwszName)
        ::CoTaskMemFree(properties.pwszName);
    if (properties.pwszVersion)
        ::CoTaskMemFree(properties.pwszVersion);
    return props;
}
