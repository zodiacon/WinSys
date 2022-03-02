#pragma once

#include "Settings.h"

struct AppSettings : Settings {
	BEGIN_SETTINGS(AppSettings)
		SETTING_STRING(Theme, L"Default");
		SETTING(MainWindowPlacement, WINDOWPLACEMENT{}, SettingType::Binary);
		SETTING(AlwaysOnTop, false, SettingType::Bool);
		SETTING(InitialTab, 0, SettingType::Int32);
	END_SETTINGS

	DEF_SETTING_STRING(Theme)
	DEF_SETTING(MainWindowPlacement, WINDOWPLACEMENT)
	DEF_SETTING(AlwaysOnTop, bool)
	DEF_SETTING(InitialTab, int)
};

