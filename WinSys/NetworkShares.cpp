#include "pch.h"
#include "NetworkShares.h"
#include "Sid.h"
#include <lm.h>

#pragma comment(lib, "netapi32")

using namespace WinSys;

namespace {
	// the share permissions' masks, as the Advanced Sharing dialog writes them
	const uint32_t FullControl = 0x1F01FF, Change = 0x1301BF, Read = 0x1200A9;

	void ReadPermissions(PSECURITY_DESCRIPTOR sd, NetworkShare& share) {
		if (!sd || !::IsValidSecurityDescriptor(sd))
			return;
		BOOL present = FALSE, defaulted = FALSE;
		PACL dacl = nullptr;
		if (!::GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted))
			return;
		share.HasPermissions = true;
		if (!present || !dacl)
			return;	// no DACL: everyone, full control
		for (DWORD i = 0; i < dacl->AceCount; i++) {
			ACE_HEADER* header;
			if (!::GetAce(dacl, i, (void**)&header))
				continue;
			PSID sid;
			ACCESS_MASK mask;
			if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
				auto ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(header);
				sid = &ace->SidStart;
				mask = ace->Mask;
			}
			else if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
				auto ace = reinterpret_cast<ACCESS_DENIED_ACE*>(header);
				sid = &ace->SidStart;
				mask = ace->Mask;
			}
			else
				continue;
			Sid s(sid);
			auto name = s.UserName();
			share.Permissions.push_back({ name.empty() ? s.AsString() : name, mask, header->AceType == ACCESS_ALLOWED_ACE_TYPE });
		}
	}

	void ReadFlags(NetworkShare& share) {
		LPBYTE buffer = nullptr;
		if (::NetShareGetInfo(nullptr, const_cast<LPWSTR>(share.Name.c_str()), 1005, &buffer) == NERR_Success && buffer) {
			share.Flags = reinterpret_cast<SHARE_INFO_1005*>(buffer)->shi1005_flags;
			::NetApiBufferFree(buffer);
		}
	}
}

std::optional<std::vector<NetworkShare>> NetworkShares::Enum(uint32_t& level) {
	NET_API_STATUS status = ERROR_ACCESS_DENIED;
	for (DWORD tryLevel : { 502u, 2u, 1u }) {
		std::vector<NetworkShare> shares;
		DWORD resume = 0;
		do {
			LPBYTE buffer = nullptr;
			DWORD read = 0, total = 0;
			status = ::NetShareEnum(nullptr, tryLevel, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
			if (status != NERR_Success && status != ERROR_MORE_DATA)
				break;
			for (DWORD i = 0; i < read; i++) {
				NetworkShare share;
				if (tryLevel == 1) {
					auto& info = reinterpret_cast<SHARE_INFO_1*>(buffer)[i];
					share.Name = info.shi1_netname ? info.shi1_netname : L"";
					share.Type = info.shi1_type;
					share.Remark = info.shi1_remark ? info.shi1_remark : L"";
				}
				else {
					// SHARE_INFO_502 starts as SHARE_INFO_2 does
					auto info = tryLevel == 502 ? (SHARE_INFO_2*)&reinterpret_cast<SHARE_INFO_502*>(buffer)[i]
						: &reinterpret_cast<SHARE_INFO_2*>(buffer)[i];
					share.Name = info->shi2_netname ? info->shi2_netname : L"";
					share.Type = info->shi2_type;
					share.Remark = info->shi2_remark ? info->shi2_remark : L"";
					share.Path = info->shi2_path ? info->shi2_path : L"";
					share.CurrentUses = info->shi2_current_uses;
					share.MaxUses = info->shi2_max_uses;
					if (tryLevel == 502)
						ReadPermissions(reinterpret_cast<SHARE_INFO_502*>(buffer)[i].shi502_security_descriptor, share);
				}
				ReadFlags(share);
				shares.push_back(std::move(share));
			}
			if (buffer)
				::NetApiBufferFree(buffer);
		} while (status == ERROR_MORE_DATA);
		if (status == NERR_Success) {
			level = tryLevel;
			return shares;
		}
		if (status != ERROR_ACCESS_DENIED)
			break;
	}
	::SetLastError(status);
	return std::nullopt;
}

std::wstring NetworkShares::TypeName(uint32_t type) {
	std::wstring name;
	switch (type & STYPE_MASK) {
		case STYPE_DISKTREE: name = L"Disk"; break;
		case STYPE_PRINTQ: name = L"Print queue"; break;
		case STYPE_DEVICE: name = L"Device"; break;
		case STYPE_IPC: name = L"IPC"; break;
		default: name = L"Type " + std::to_wstring(type & STYPE_MASK); break;
	}
	if (type & STYPE_SPECIAL)
		name += L", special";
	if (type & STYPE_TEMPORARY)
		name += L", temporary";
	return name;
}

std::wstring NetworkShares::RightsName(uint32_t mask) {
	switch (mask) {
		case FullControl: return L"Full Control";
		case Change: return L"Change";
		case Read: return L"Read";
	}
	WCHAR text[16];
	::StringCchPrintf(text, _countof(text), L"0x%X", mask);
	return text;
}

std::wstring NetworkShares::CachingName(uint32_t flags) {
	switch (flags & CSC_MASK) {
		case CSC_CACHE_MANUAL_REINT: return L"Manual";
		case CSC_CACHE_AUTO_REINT: return L"Automatic (documents)";
		case CSC_CACHE_VDO: return L"Automatic (programs)";
		case CSC_CACHE_NONE: return L"None";
	}
	return L"";
}
