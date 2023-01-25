#include "pch.h"
#include "ThreadInfo.h"

using namespace WinSys;

ThreadState ThreadInfo::GetThreadState() const {
	return (ThreadState)NativeInfo->ThreadState;
}

WaitReason WinSys::ThreadInfo::GetWaitReason() const {
	return (WaitReason)NativeInfo->WaitReason;
}
