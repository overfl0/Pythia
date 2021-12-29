#pragma once
#include "stdafx.h"
#include <string>

std::string GetCurrentWorkingDir();
std::wstring getPathDirectory(const std::wstring& path);
std::string getPathDirectory(const std::string& path);
tstring getProgramPath();
tstring getProgramDirectory();
tstring getDllPath();
tstring getPythonPath();
