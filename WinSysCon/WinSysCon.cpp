// WinSysCon.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <ProcessManager.h>

#pragma comment(lib, "ntdll")

using namespace WinSys;

void PerfTest(bool WithThreads) {
	ProcessManager pm;
	LARGE_INTEGER start, end, freq;
	::QueryPerformanceFrequency(&freq);
	for (int i = 0; i < 20; i++) {
		::QueryPerformanceCounter(&start);
		auto count = pm.EnumProcesses(WithThreads, 0);
		::QueryPerformanceCounter(&end);
		auto diff = end.QuadPart - start.QuadPart;
		printf("time: %lld (%lld msec)\n", diff, diff * 1000 / freq.QuadPart);

		::Sleep(1000);
	}
}

int main() {
	ProcessManager pm;
	auto count = pm.EnumProcessesAndThreads();
	printf("%u processes found\n", count);

	for (auto& p : pm.GetProcesses()) {
		printf("%6u: %ws PPID: %6u Threads: %3u\n",
			p->Id, p->GetImageName().c_str(), p->ParentId, p->NativeInfo->NumberOfThreads);
		for (auto& t : p->GetThreads()) {
			printf("\tTID: %6u TEB: 0x%p\n",
				t->Id, t->ExtendedInfo->TebBase);
		}
	}
	return 0;
}

