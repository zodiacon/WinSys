#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace WinSys {
	//
	// A compute system the Host Compute Service runs (HCS: Hyper-V's VMs, WSL 2's VM, Windows Sandbox's, containers and
	// their utility VMs), or one of Hyper-V's VMs that isn't running (only Hyper-V's configuration has those)
	//
	struct ComputeSystem {
		std::wstring Id;			// upper case, without braces: a VM's GUID, a Docker container's ID
		std::wstring Name;			// HCS's, else Hyper-V's (its VM name); empty if neither has one (WSL's VM)
		std::wstring Owner;			// who created it: "VMMS" (Hyper-V), "WSL", "CmService" (Windows Sandbox), "docker"...
		std::wstring SystemType;	// "VirtualMachine" or "Container"
		std::wstring State;			// HCS's ("Running", "Paused", "SavedAsTemplate"); else Hyper-V's ("Running", "Off", "Saved")
		std::wstring RuntimeOsType;	// "Windows", "Linux" when HCS has it
		std::wstring HostingSystemId;	// a Hyper-V isolated container's utility VM
		uint32_t ProcessorCount{ 0 };	// virtual processors; 0 if unknown (not running, a container)
		uint64_t AssignedMemory{ 0 };	// bytes; 0 if unknown
		bool InHcs{ false };		// HCS runs it (running, paused or saved)
		bool InHyperV{ false };		// one of Hyper-V's VMs (root\virtualization\v2)
	};

	struct VirtualMachines final {
		// HCS's compute systems, with their processors and memory, and Hyper-V's VMs that HCS hasn't (off, saved),
		// by Id; nothing if neither can be read, with the last error set (HCS's): both need an administrator (or Hyper-V
		// Administrators). COM must be initialized on the thread (WMI)
		[[nodiscard]] static std::optional<std::vector<ComputeSystem>> Enumerate();

		// HcsEnumerateComputeSystems' answer (a JSON array); empty if it isn't one
		[[nodiscard]] static std::vector<ComputeSystem> ParseComputeSystems(std::string_view json);
		// HcsGetComputeSystemProperties' answer to a Memory query: the virtual processors and the assigned memory
		static void ParseMemoryProperties(std::string_view json, ComputeSystem& system);

		// a VM's ID from the account its worker (vmwp.exe) and security process (vmsp.exe) run as:
		// "NT VIRTUAL MACHINE\4BF6AFEE-D1B6-4C85-A616-4F4A7AAEB246"; empty for any other account
		[[nodiscard]] static std::wstring IdFromAccount(std::wstring_view account);
		// a VM's ID from a command line: vmwp.exe's first argument, wslhost.exe's --vm-id; empty if it has none
		[[nodiscard]] static std::wstring IdFromCommandLine(std::wstring_view commandLine);
		// upper case, braces removed; empty if it isn't a GUID
		[[nodiscard]] static std::wstring NormalizeId(std::wstring_view id);

		// what it is: "Hyper-V VM", "WSL 2", "Windows Sandbox", "Container", "Utility VM (docker)"...
		[[nodiscard]] static std::wstring KindText(ComputeSystem const& system);
		// its name, else what stands for one ("WSL 2"), else its ID
		[[nodiscard]] static std::wstring DisplayName(ComputeSystem const& system);
		// the state in words ("Saved as template" for HCS's SavedAsTemplate); empty if unknown
		[[nodiscard]] static std::wstring StateText(ComputeSystem const& system);
		// Msvm_ComputerSystem's EnabledState ("Running", "Off", "Saved"...)
		[[nodiscard]] static std::wstring HyperVStateName(uint32_t enabledState);
	};
}
