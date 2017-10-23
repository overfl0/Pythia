#pragma once

#include "stdafx.h"

//void getDirectories(std::wstring const & fileExtension = L"");
//#include <filesystem>

typedef std::unordered_map<std::string, std::wstring> modules_t;
modules_t getPythiaModulesSources();
