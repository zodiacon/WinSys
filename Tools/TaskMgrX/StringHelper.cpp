#include "pch.h"
#include "StringHelper.h"
#include "Processes.h"
#include <atltime.h>

using namespace WinSys;

PCWSTR StringHelper::PriorityClassToString(WinSys::ProcessPriorityClass pc) {
	switch (pc) {
		using enum WinSys::ProcessPriorityClass;
		case Normal: return L"Normal (8)";
		case AboveNormal: return L"Above Normal (10)";
		case BelowNormal: return L"Below Normal (6)";
		case High: return L"High (13)";
		case Idle: return L"Idle (4)";
		case Realtime: return L"Realtime (24)";
	}
	return L"";
}

CString StringHelper::FormatSize(long long size) {
	CString result;
	int len = ::GetNumberFormat(LOCALE_USER_DEFAULT, 0, std::to_wstring(size).c_str(), nullptr, result.GetBufferSetLength(32), 32);
	return result.Left(len - 4);
}

CString StringHelper::TimeToString(int64_t time, bool includeMS) {
	if (time == 0)
		return L"";
	auto str = CTime(*(FILETIME*)&time).Format(L"%x %X");
	if (includeMS) {
		str.Format(L"%s.%03d", str, (time / 10000) % 1000);
	}
	return str;
}

CString StringHelper::TimeSpanToString(long long ts) {
	auto str = CTimeSpan(ts / 10000000).Format(L"%D.%H:%M:%S");

	str.Format(L"%s.%03d", str, (ts / 10000) % 1000);
	return str;
}

PCWSTR StringHelper::IntegrityLevelToString(IntegrityLevel level) {
	switch (level) {
		case IntegrityLevel::High: return L"High";
		case IntegrityLevel::Medium: return L"Medium";
		case IntegrityLevel::MediumPlus: return L"Medium+";
		case IntegrityLevel::Low: return L"Low";
		case IntegrityLevel::System: return L"System";
		case IntegrityLevel::Untrusted: return L"Untrusted";
	}
	return L"Unknown";
}

PCWSTR StringHelper::VirtualizationStateToString(VirtualizationState state) {
	switch (state) {
		case VirtualizationState::Disabled: return L"Disabled";
		case VirtualizationState::Enabled: return L"Enabled";
		case VirtualizationState::NotAllowed: return L"Not Allowed";
	}
	return L"Unknown";
}

CString StringHelper::ProcessAttributesToString(ProcessAttributes attributes) {
	CString text;

	static const struct {
		ProcessAttributes Attribute;
		PCWSTR Text;
	} attribs[] = {
		{ ProcessAttributes::Managed, L"Managed" },
		{ ProcessAttributes::Immersive, L"Immersive" },
		{ ProcessAttributes::Protected, L"Protected" },
		{ ProcessAttributes::Secure, L"Secure" },
		{ ProcessAttributes::Service, L"Service" },
		{ ProcessAttributes::InJob, L"Job" },
		{ ProcessAttributes::Wow64, L"Wow64" },
		{ ProcessAttributes::Pico, L"Pico" },
		{ ProcessAttributes::Suspended, L"Suspended" },
	};

	for (auto& item : attribs)
		if ((item.Attribute & attributes) == item.Attribute)
			text += CString(item.Text) + ", ";
	if (!text.IsEmpty())
		text = text.Mid(0, text.GetLength() - 2);
	return text;
}

CString StringHelper::ProcessProtectionToString(ProcessProtection pp) {
	if (pp.Level == 0)
		return L"";

	CString signer;
	switch (pp.Signer) {
		case ProcessProtectionSigner::Authenticode: signer = L"Authenticode"; break;
		case ProcessProtectionSigner::CodeGen: signer = L"CodeGen"; break;
		case ProcessProtectionSigner::Antimalware: signer = L"AntiMalware"; break;
		case ProcessProtectionSigner::Lsa: signer = L"LSA"; break;
		case ProcessProtectionSigner::Windows: signer = L"Windows"; break;
		case ProcessProtectionSigner::WinTcb: signer = L"WinTcb"; break;
		case ProcessProtectionSigner::WinSystem: signer = L"WinSystem"; break;
		case ProcessProtectionSigner::App: signer = L"App"; break;
	}

	CString type;
	switch (pp.Type) {
		case 1: type = L"Protected Light"; break;
		case 2: type = L"Protected";
	}

	return signer + L"-" + type;
}

PCWSTR StringHelper::IoPriorityToString(WinSys::IoPriority io) {
	switch (io) {
		case IoPriority::Critical: return L"Critical";
		case IoPriority::High: return L"High";
		case IoPriority::Low: return L"Low";
		case IoPriority::Normal: return L"Normal";
		case IoPriority::VeryLow: return L"Very Low";
	}
	return L"";
}
