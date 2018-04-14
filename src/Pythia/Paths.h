#pragma once

#include <string>

std::string GetCurrentWorkingDir();
std::wstring getPathDirectory(const std::wstring& path);
std::string getPathDirectory(const std::string& path);
std::wstring getProgramPath();
std::wstring getProgramDirectory();
std::wstring getDllPath();
std::wstring getPythonPath();
