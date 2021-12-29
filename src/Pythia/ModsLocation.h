#pragma once

#include "stdafx.h"

//void getDirectories(std::wstring const & fileExtension = L"");
//#include <filesystem>

typedef std::unordered_map<std::string, tstring> modules_t;
modules_t getPythiaModulesSources();
