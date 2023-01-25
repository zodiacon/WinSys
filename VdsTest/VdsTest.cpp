// VdsTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <WinSys.h>
#include "VirtualDiskService.h"
#include <stdio.h>

int main() {
	using namespace WinSys::Vds;

	::CoInitializeEx(nullptr, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE);

	VirtualDiskService svc;
	if (svc.Load()) {
		auto props = svc.GetProperties();
		printf("Version: %ws\n", props.Version.c_str());

		for (auto& provider : svc.QueryProviders(VdsProviderMask::All)) {
			auto props = provider.GetProperties();
			if (props) {
				printf("%ws (%ws)\n", props->Name.c_str(), props->Version.c_str());
			}
		}
	}

}
