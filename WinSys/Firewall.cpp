#include "pch.h"
#include "Firewall.h"
#include <netfw.h>
#include <Shlwapi.h>
#include <wrl/client.h>
#include <wil/resource.h>

#pragma comment(lib, "shlwapi")

using Microsoft::WRL::ComPtr;

namespace WinSys {
	namespace {
		std::wstring ToString(BSTR s) {
			return s ? std::wstring(s, ::SysStringLen(s)) : std::wstring();
		}

		template<typename T, typename F>
		std::wstring GetString(T* object, F getter) {
			wil::unique_bstr value;
			if (SUCCEEDED((object->*getter)(value.put())))
				return ToString(value.get());
			return L"";
		}

		// "@FirewallAPI.dll,-25000" and "@{package?ms-resource://...}" as the text they name; else as is
		std::wstring Resolve(std::wstring const& text) {
			if (text.empty() || text[0] != L'@')
				return text;
			WCHAR resolved[1024];
			if (SUCCEEDED(::SHLoadIndirectString(text.c_str(), resolved, _countof(resolved), nullptr)))
				return resolved;
			// a package's resource whose package (version) isn't installed anymore, as rules outlive the package
			// versions that added them ("@{Microsoft.LockApp_10.0.28000.3181_neutral__cw5n1h2txyewy?ms-resource://..."):
			// the package's name, as nothing can resolve it (Get-NetFirewallRule shows the raw string)
			if (text.starts_with(L"@{")) {
				auto end = text.find_first_of(L"_?}", 2);
				if (end != std::wstring::npos && end > 2)
					return text.substr(2, end - 2);
			}
			return text;
		}

		HRESULT GetPolicy2(ComPtr<INetFwPolicy2>& policy) {
			return ::CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&policy));
		}

		FirewallRule Describe(INetFwRule* rule) {
			FirewallRule r;
			r.RawName = GetString(rule, &INetFwRule::get_Name);
			r.Name = Resolve(r.RawName);
			r.Description = Resolve(GetString(rule, &INetFwRule::get_Description));
			r.RawGrouping = GetString(rule, &INetFwRule::get_Grouping);
			r.Grouping = Resolve(r.RawGrouping);
			r.Application = GetString(rule, &INetFwRule::get_ApplicationName);
			r.Service = GetString(rule, &INetFwRule::get_ServiceName);
			r.LocalPorts = GetString(rule, &INetFwRule::get_LocalPorts);
			r.RemotePorts = GetString(rule, &INetFwRule::get_RemotePorts);
			r.LocalAddresses = GetString(rule, &INetFwRule::get_LocalAddresses);
			r.RemoteAddresses = GetString(rule, &INetFwRule::get_RemoteAddresses);
			r.IcmpTypes = GetString(rule, &INetFwRule::get_IcmpTypesAndCodes);
			r.InterfaceTypes = GetString(rule, &INetFwRule::get_InterfaceTypes);
			LONG protocol = NET_FW_IP_PROTOCOL_ANY;
			if (SUCCEEDED(rule->get_Protocol(&protocol)))
				r.Protocol = protocol;
			long profiles = 0;
			if (SUCCEEDED(rule->get_Profiles(&profiles)))
				r.Profiles = (uint32_t)profiles;
			NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
			if (SUCCEEDED(rule->get_Direction(&direction)))
				r.Inbound = direction == NET_FW_RULE_DIR_IN;
			NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
			if (SUCCEEDED(rule->get_Action(&action)))
				r.Allow = action == NET_FW_ACTION_ALLOW;
			VARIANT_BOOL flag = VARIANT_FALSE;
			if (SUCCEEDED(rule->get_Enabled(&flag)))
				r.Enabled = flag != VARIANT_FALSE;
			flag = VARIANT_FALSE;
			if (SUCCEEDED(rule->get_EdgeTraversal(&flag)))
				r.EdgeTraversal = flag != VARIANT_FALSE;
			ComPtr<INetFwRule3> rule3;
			if (SUCCEEDED(rule->QueryInterface(IID_PPV_ARGS(&rule3))))
				r.PackageId = GetString(rule3.Get(), &INetFwRule3::get_LocalAppPackageId);
			return r;
		}

		// calls the callback with each rule until it returns false; the HRESULT of the enumeration
		template<typename F>
		HRESULT ForEachRule(F&& callback) {
			ComPtr<INetFwPolicy2> policy;
			auto hr = GetPolicy2(policy);
			if (FAILED(hr))
				return hr;
			ComPtr<INetFwRules> rules;
			if (FAILED(hr = policy->get_Rules(&rules)))
				return hr;
			ComPtr<IUnknown> unknown;
			if (FAILED(hr = rules->get__NewEnum(&unknown)))
				return hr;
			ComPtr<IEnumVARIANT> it;
			if (FAILED(hr = unknown.As(&it)))
				return hr;
			for (;;) {
				VARIANT item;
				::VariantInit(&item);
				ULONG fetched = 0;
				if (it->Next(1, &item, &fetched) != S_OK || fetched == 0)
					break;
				ComPtr<INetFwRule> rule;
				bool more = true;
				if (item.vt == VT_DISPATCH && item.pdispVal && SUCCEEDED(item.pdispVal->QueryInterface(IID_PPV_ARGS(&rule))))
					more = callback(rule.Get());
				::VariantClear(&item);
				if (!more)
					break;
			}
			return S_OK;
		}
	}

	std::optional<std::vector<FirewallRule>> Firewall::EnumRules() {
		std::vector<FirewallRule> rules;
		auto hr = ForEachRule([&](INetFwRule* rule) {
			rules.push_back(Describe(rule));
			return true;
			});
		if (FAILED(hr)) {
			::SetLastError(hr);
			return {};
		}
		return rules;
	}

	std::optional<FirewallPolicy> Firewall::GetPolicy() {
		ComPtr<INetFwPolicy2> policy;
		auto hr = GetPolicy2(policy);
		if (FAILED(hr)) {
			::SetLastError(hr);
			return {};
		}
		FirewallPolicy result;
		long current = 0;
		if (SUCCEEDED(policy->get_CurrentProfileTypes(&current)))
			result.CurrentProfiles = (uint32_t)current;
		for (auto type : { NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC }) {
			FirewallProfile profile;
			profile.Type = type;
			VARIANT_BOOL flag = VARIANT_FALSE;
			if (SUCCEEDED(policy->get_FirewallEnabled(type, &flag)))
				profile.Enabled = flag != VARIANT_FALSE;
			flag = VARIANT_FALSE;
			if (SUCCEEDED(policy->get_BlockAllInboundTraffic(type, &flag)))
				profile.BlockAllInbound = flag != VARIANT_FALSE;
			NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
			if (SUCCEEDED(policy->get_DefaultInboundAction(type, &action)))
				profile.InboundAllowed = action == NET_FW_ACTION_ALLOW;
			action = NET_FW_ACTION_ALLOW;
			if (SUCCEEDED(policy->get_DefaultOutboundAction(type, &action)))
				profile.OutboundAllowed = action == NET_FW_ACTION_ALLOW;
			result.Profiles.push_back(profile);
		}
		return result;
	}

	bool Firewall::SameRule(FirewallRule const& a, FirewallRule const& b) {
		return a.RawName == b.RawName && a.RawGrouping == b.RawGrouping && a.Inbound == b.Inbound && a.Allow == b.Allow
			&& a.Protocol == b.Protocol && a.Profiles == b.Profiles && a.LocalPorts == b.LocalPorts && a.RemotePorts == b.RemotePorts
			&& a.LocalAddresses == b.LocalAddresses && a.RemoteAddresses == b.RemoteAddresses && a.IcmpTypes == b.IcmpTypes
			&& ::_wcsicmp(a.Application.c_str(), b.Application.c_str()) == 0 && ::_wcsicmp(a.Service.c_str(), b.Service.c_str()) == 0
			&& a.PackageId == b.PackageId && a.InterfaceTypes == b.InterfaceTypes;
	}

	bool Firewall::SetEnabled(FirewallRule const& target, bool enabled) {
		HRESULT result = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
		auto hr = ForEachRule([&](INetFwRule* rule) {
			if (!SameRule(Describe(rule), target))
				return true;
			result = rule->put_Enabled(enabled ? VARIANT_TRUE : VARIANT_FALSE);
			return false;
			});
		if (FAILED(hr))
			result = hr;
		if (FAILED(result)) {
			::SetLastError(result == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) ? ERROR_NOT_FOUND : result);
			return false;
		}
		return true;
	}

	std::wstring Firewall::ProtocolName(int32_t protocol) {
		switch (protocol) {
			case 1: return L"ICMPv4";
			case 2: return L"IGMP";
			case 6: return L"TCP";
			case 17: return L"UDP";
			case 41: return L"IPv6";
			case 47: return L"GRE";
			case 58: return L"ICMPv6";
			case 256: return L"Any";
		}
		return std::to_wstring(protocol);
	}

	std::wstring Firewall::ProfilesText(uint32_t profiles) {
		const uint32_t all = NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC;
		if ((profiles & all) == all)
			return L"All";
		std::wstring text;
		for (auto [bit, name] : { std::pair{ (uint32_t)NET_FW_PROFILE2_DOMAIN, L"Domain" }, { (uint32_t)NET_FW_PROFILE2_PRIVATE, L"Private" },
			{ (uint32_t)NET_FW_PROFILE2_PUBLIC, L"Public" } })
			if (profiles & bit)
				text += (text.empty() ? L"" : L", ") + std::wstring(name);
		return text;
	}
}
