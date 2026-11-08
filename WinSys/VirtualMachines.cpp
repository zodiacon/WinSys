// Not pch.h, which turns the standard library's exceptions off (_HAS_EXCEPTIONS 0): nlohmann::json's parser makes a
// parse_error, which holds a std::runtime_error, on bad input even when it throws nothing, and that class's vtable has a
// different size without exceptions; linked into the app, which has them, LTCG warns (C4743) and one of the two is used.
// Compiled as the app is, it's the same. Nothing here needs the native API (phnt)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <wbemidl.h>
#include <string>
#include <vector>
#include <optional>
#include "VirtualMachines.h"
#include <wil/com.h>
#include <wil/resource.h>
#include <algorithm>
#include <cwctype>
// WinSys reports errors without exceptions, and its callers catch none: nlohmann's failures abort instead of throwing
// (JSON_NOEXCEPTION), so the parsing below asks for no exceptions (a discarded value on bad input) and checks every
// value's type before reading it
#define JSON_NOEXCEPTION
#include <nlohmann/json.hpp>

using namespace WinSys;
using json = nlohmann::json;

namespace {
	// the Host Compute Service's API (computecore.dll, Windows 10 1809 on); loaded on first use, as it's missing
	// without the virtualization features
	using HCS_OPERATION = HANDLE;
	using HCS_SYSTEM = HANDLE;
	struct HcsApi {
		HCS_OPERATION(WINAPI* CreateOperation)(void const* context, void* callback);
		void(WINAPI* CloseOperation)(HCS_OPERATION operation);
		HRESULT(WINAPI* EnumerateComputeSystems)(PCWSTR query, HCS_OPERATION operation);
		HRESULT(WINAPI* WaitForOperationResult)(HCS_OPERATION operation, DWORD timeoutMs, PWSTR* resultDocument);
		HRESULT(WINAPI* OpenComputeSystem)(PCWSTR id, DWORD requestedAccess, HCS_SYSTEM* computeSystem);
		void(WINAPI* CloseComputeSystem)(HCS_SYSTEM computeSystem);
		HRESULT(WINAPI* GetComputeSystemProperties)(HCS_SYSTEM computeSystem, HCS_OPERATION operation, PCWSTR propertyQuery);
		bool Loaded{ false };
	};

	HcsApi const& Hcs() {
		static HcsApi const api = [] {
			HcsApi a{};
			auto dll = ::LoadLibraryExW(L"computecore.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
			if (!dll)
				return a;
			a.CreateOperation = (decltype(a.CreateOperation))::GetProcAddress(dll, "HcsCreateOperation");
			a.CloseOperation = (decltype(a.CloseOperation))::GetProcAddress(dll, "HcsCloseOperation");
			a.EnumerateComputeSystems = (decltype(a.EnumerateComputeSystems))::GetProcAddress(dll, "HcsEnumerateComputeSystems");
			a.WaitForOperationResult = (decltype(a.WaitForOperationResult))::GetProcAddress(dll, "HcsWaitForOperationResult");
			a.OpenComputeSystem = (decltype(a.OpenComputeSystem))::GetProcAddress(dll, "HcsOpenComputeSystem");
			a.CloseComputeSystem = (decltype(a.CloseComputeSystem))::GetProcAddress(dll, "HcsCloseComputeSystem");
			a.GetComputeSystemProperties = (decltype(a.GetComputeSystemProperties))::GetProcAddress(dll, "HcsGetComputeSystemProperties");
			a.Loaded = a.CreateOperation && a.CloseOperation && a.EnumerateComputeSystems && a.WaitForOperationResult
				&& a.OpenComputeSystem && a.CloseComputeSystem && a.GetComputeSystemProperties;
			return a;
			}();
		return api;
	}

	std::string ToUtf8(std::wstring_view text) {
		std::string result;
		int size = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0, nullptr, nullptr);
		if (size > 0) {
			result.resize(size);
			::WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), result.data(), size, nullptr, nullptr);
		}
		return result;
	}

	std::wstring FromUtf8(std::string const& text) {
		std::wstring result;
		int size = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0);
		if (size > 0) {
			result.resize(size);
			::MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), result.data(), size);
		}
		return result;
	}

	// an object's member: a string, a number, an object; empty or zero if it's missing or of another type
	std::wstring Text(json const& object, char const* key) {
		auto it = object.find(key);
		return it != object.end() && it->is_string() ? FromUtf8(it->get_ref<std::string const&>()) : std::wstring();
	}

	uint64_t Number(json const& object, char const* key) {
		auto it = object.find(key);
		return it != object.end() && it->is_number_unsigned() ? it->get<uint64_t>()
			: it != object.end() && it->is_number_integer() && it->get<int64_t>() > 0 ? (uint64_t)it->get<int64_t>() : 0;
	}

	json const* Member(json const& object, char const* key) {
		if (!object.is_object())
			return nullptr;
		auto it = object.find(key);
		return it != object.end() && it->is_object() ? &*it : nullptr;
	}

	// runs an HCS call to its end: the result document, or nothing (the last error set)
	template<typename Call>
	std::optional<std::wstring> RunOperation(Call&& call) {
		auto& hcs = Hcs();
		auto operation = hcs.CreateOperation(nullptr, nullptr);
		if (!operation) {
			::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return std::nullopt;
		}
		auto hr = call(operation);
		PWSTR document = nullptr;
		if (SUCCEEDED(hr))
			hr = hcs.WaitForOperationResult(operation, 10000, &document);
		std::wstring result = document ? document : L"";
		if (document)
			::LocalFree(document);
		hcs.CloseOperation(operation);
		if (FAILED(hr)) {
			::SetLastError((DWORD)hr);
			return std::nullopt;
		}
		return result;
	}

	// Hyper-V's VMs (Msvm_ComputerSystem, but the host's own entry): ID, name, state
	bool ReadHyperV(std::vector<ComputeSystem>& systems) {
		wil::com_ptr_nothrow<IWbemLocator> locator;
		auto hr = ::CoCreateInstance(__uuidof(WbemLocator), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator));
		wil::com_ptr_nothrow<IWbemServices> services;
		if (SUCCEEDED(hr)) {
			wil::unique_bstr ns(::SysAllocString(L"ROOT\\virtualization\\v2"));
			hr = locator->ConnectServer(ns.get(), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
		}
		if (SUCCEEDED(hr))
			hr = ::CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
				RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
		wil::com_ptr_nothrow<IEnumWbemClassObject> rows;
		if (SUCCEEDED(hr)) {
			wil::unique_bstr language(::SysAllocString(L"WQL"));
			wil::unique_bstr query(::SysAllocString(L"SELECT Name, ElementName, EnabledState FROM Msvm_ComputerSystem"));
			hr = services->ExecQuery(language.get(), query.get(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &rows);
		}
		if (FAILED(hr))
			return false;

		auto text = [](IWbemClassObject* row, PCWSTR name) {
			wil::unique_variant value;
			return SUCCEEDED(row->Get(name, 0, &value, nullptr, nullptr)) && value.vt == VT_BSTR && value.bstrVal
				? std::wstring(value.bstrVal) : std::wstring();
		};
		bool any = false;
		for (;;) {
			wil::com_ptr_nothrow<IWbemClassObject> row;
			ULONG count = 0;
			if (rows->Next(WBEM_INFINITE, 1, &row, &count) != WBEM_S_NO_ERROR || count == 0)
				break;
			// a VM's Name is its GUID; the host's is the computer's name
			auto id = VirtualMachines::NormalizeId(text(row.get(), L"Name"));
			if (id.empty())
				continue;
			wil::unique_variant state;
			uint32_t enabled = 0;
			if (SUCCEEDED(row->Get(L"EnabledState", 0, &state, nullptr, nullptr)) && SUCCEEDED(::VariantChangeType(&state, &state, 0, VT_UI4)))
				enabled = state.ulVal;
			any = true;
			auto it = std::ranges::find(systems, id, &ComputeSystem::Id);
			if (it == systems.end()) {
				ComputeSystem s;
				s.Id = id;
				s.Owner = L"VMMS";
				s.SystemType = L"VirtualMachine";
				it = systems.insert(systems.end(), std::move(s));
			}
			it->InHyperV = true;
			if (it->Name.empty())
				it->Name = text(row.get(), L"ElementName");
			// HCS doesn't say for Hyper-V's VMs (Running for others): Hyper-V does
			if (it->State.empty())
				it->State = VirtualMachines::HyperVStateName(enabled);
		}
		return any || SUCCEEDED(hr);
	}
}

std::wstring VirtualMachines::NormalizeId(std::wstring_view id) {
	if (id.size() == 38 && id.front() == L'{' && id.back() == L'}')
		id = id.substr(1, 36);
	if (id.size() != 36)
		return {};
	std::wstring result;
	for (size_t i = 0; i < id.size(); i++) {
		auto c = id[i];
		bool dash = i == 8 || i == 13 || i == 18 || i == 23;
		if (dash ? c != L'-' : !std::iswxdigit(c))
			return {};
		result += (wchar_t)std::towupper(c);
	}
	return result;
}

std::wstring VirtualMachines::IdFromAccount(std::wstring_view account) {
	constexpr std::wstring_view prefix = L"NT VIRTUAL MACHINE\\";
	if (account.size() <= prefix.size() || _wcsnicmp(account.data(), prefix.data(), prefix.size()) != 0)
		return {};
	return NormalizeId(account.substr(prefix.size()));
}

std::wstring VirtualMachines::IdFromCommandLine(std::wstring_view commandLine) {
	// wslhost.exe: "--vm-id {guid}"
	if (auto pos = commandLine.find(L"--vm-id"); pos != std::wstring_view::npos) {
		auto start = commandLine.find_first_not_of(L" \t=", pos + 7);
		if (start == std::wstring_view::npos)
			return {};
		auto end = commandLine.find_first_of(L" \t", start);
		return NormalizeId(commandLine.substr(start, end == std::wstring_view::npos ? std::wstring_view::npos : end - start));
	}
	// vmwp.exe: "C:\Windows\System32\vmwp.exe" 4BF6AFEE-D1B6-4C85-A616-4F4A7AAEB246 0x408 (the program, then the ID)
	size_t pos = 0;
	if (!commandLine.empty() && commandLine[0] == L'"') {
		pos = commandLine.find(L'"', 1);
		if (pos == std::wstring_view::npos)
			return {};
		pos++;
	}
	else
		pos = commandLine.find_first_of(L" \t");
	if (pos == std::wstring_view::npos)
		return {};
	auto start = commandLine.find_first_not_of(L" \t", pos);
	if (start == std::wstring_view::npos)
		return {};
	auto end = commandLine.find_first_of(L" \t", start);
	return NormalizeId(commandLine.substr(start, end == std::wstring_view::npos ? std::wstring_view::npos : end - start));
}

std::vector<ComputeSystem> VirtualMachines::ParseComputeSystems(std::string_view text) {
	std::vector<ComputeSystem> systems;
	auto doc = json::parse(text.begin(), text.end(), nullptr, false);
	if (!doc.is_array())
		return systems;
	for (auto& item : doc) {
		if (!item.is_object())
			continue;
		ComputeSystem s;
		auto id = Text(item, "Id");
		// a VM's is a GUID; a container's is Docker's (64 hex digits), kept as it is (in upper case)
		s.Id = NormalizeId(id);
		if (s.Id.empty()) {
			s.Id = id;
			std::ranges::transform(s.Id, s.Id.begin(), [](wchar_t c) { return (wchar_t)std::towupper(c); });
		}
		if (s.Id.empty())
			continue;
		s.Name = Text(item, "Name");
		s.Owner = Text(item, "Owner");
		s.SystemType = Text(item, "SystemType");
		s.State = Text(item, "State");
		s.RuntimeOsType = Text(item, "RuntimeOsType");
		s.HostingSystemId = NormalizeId(Text(item, "HostingSystemId"));
		if (s.HostingSystemId.empty())
			s.HostingSystemId = Text(item, "HostingSystemId");
		s.InHcs = true;
		systems.push_back(std::move(s));
	}
	return systems;
}

void VirtualMachines::ParseMemoryProperties(std::string_view text, ComputeSystem& system) {
	if (text.empty())
		return;
	auto doc = json::parse(text.begin(), text.end(), nullptr, false);
	auto memory = Member(doc, "Memory");
	if (!memory)
		return;
	// AssignedMemory and the nodes' usage are in 4 KB pages
	if (auto vm = Member(*memory, "VirtualMachineMemory"))
		system.AssignedMemory = Number(*vm, "AssignedMemory") * 4096;
	auto nodes = memory->find("VirtualNodes");
	if (nodes != memory->end() && nodes->is_array()) {
		uint32_t processors = 0;
		for (auto& node : *nodes)
			if (node.is_object())
				processors += (uint32_t)Number(node, "VirtualProcessorCount");
		system.ProcessorCount = processors;
	}
}

std::optional<std::vector<ComputeSystem>> VirtualMachines::Enumerate() {
	std::vector<ComputeSystem> systems;
	DWORD hcsError = ERROR_PROC_NOT_FOUND;
	auto& hcs = Hcs();
	bool hcsRead = false;
	if (hcs.Loaded) {
		auto list = RunOperation([&](HANDLE op) { return hcs.EnumerateComputeSystems(nullptr, op); });
		if (list) {
			hcsRead = true;
			systems = ParseComputeSystems(ToUtf8(*list));
			// each one's processors and memory (a VM's; a container has none of its own)
			for (auto& s : systems) {
				if (s.SystemType != L"VirtualMachine")
					continue;
				HCS_SYSTEM handle = nullptr;
				// the access HCS's documentation asks for (it refuses GENERIC_READ); reading properties changes nothing
				if (FAILED(hcs.OpenComputeSystem(s.Id.c_str(), GENERIC_ALL, &handle)) || !handle)
					continue;
				auto properties = RunOperation([&](HANDLE op) {
					return hcs.GetComputeSystemProperties(handle, op, LR"({"PropertyTypes":["Memory"]})");
					});
				hcs.CloseComputeSystem(handle);
				if (properties)
					ParseMemoryProperties(ToUtf8(*properties), s);
			}
		}
		else
			hcsError = ::GetLastError();
	}
	bool hyperV = ReadHyperV(systems);
	if (!hcsRead && !hyperV) {
		::SetLastError(hcsError);
		return std::nullopt;
	}
	return systems;
}

std::wstring VirtualMachines::KindText(ComputeSystem const& s) {
	bool container = s.SystemType == L"Container";
	if (container)
		return s.Owner.empty() ? L"Container" : L"Container (" + s.Owner + L")";
	if (_wcsicmp(s.Owner.c_str(), L"VMMS") == 0)
		return L"Hyper-V VM";
	if (_wcsicmp(s.Owner.c_str(), L"WSL") == 0)
		return L"WSL 2";
	if (_wcsicmp(s.Owner.c_str(), L"CmService") == 0)
		return s.State == L"SavedAsTemplate" ? L"Windows Sandbox (template)" : L"Windows Sandbox";
	// a Hyper-V isolated container's, or a VM some other program made
	return s.Owner.empty() ? L"VM" : L"Utility VM (" + s.Owner + L")";
}

std::wstring VirtualMachines::DisplayName(ComputeSystem const& s) {
	if (!s.Name.empty())
		return s.Name;
	if (_wcsicmp(s.Owner.c_str(), L"WSL") == 0)
		return L"WSL 2";
	if (_wcsicmp(s.Owner.c_str(), L"CmService") == 0)
		return L"Windows Sandbox";
	// a Docker container's ID: its short form, as docker ps shows
	if (s.SystemType == L"Container" && s.Id.size() == 64)
		return s.Id.substr(0, 12);
	return s.Id;
}

std::wstring VirtualMachines::StateText(ComputeSystem const& s) {
	// HCS's names are identifiers ("SavedAsTemplate"): words apart
	std::wstring text;
	for (auto c : s.State) {
		if (std::iswupper(c) && !text.empty()) {
			text += L' ';
			c = (wchar_t)std::towlower(c);
		}
		text += c;
	}
	return text;
}

std::wstring VirtualMachines::HyperVStateName(uint32_t state) {
	switch (state) {
		case 2: return L"Running";
		case 3: return L"Off";
		case 6: return L"Saved";
		case 9: return L"Paused";
		case 10: return L"Starting";
		case 11: return L"Reset";
		case 32768: return L"Paused";
		case 32769: return L"Saved";
		case 32770: return L"Starting";
		case 32771: return L"Snapshotting";
		case 32773: return L"Saving";
		case 32774: return L"Stopping";
		case 32776: return L"Pausing";
		case 32777: return L"Resuming";
		case 32779: return L"Fast saved";
		case 32780: return L"Fast saving";
	}
	return state ? L"State " + std::to_wstring(state) : L"Unknown";
}
