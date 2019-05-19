#include "stdafx.h"
#include <string>
#include "Logger.h"

#ifdef _WIN32
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

std::string GetCurrentWorkingDir()
{
    char buff[FILENAME_MAX + 1];
    GetCurrentDir(buff, FILENAME_MAX);
    std::string current_working_dir(buff);
    return current_working_dir;
}

std::wstring getPathDirectory(const std::wstring& path)
{
    // Returns the whole string if no backslash is present
    return path.substr(0, path.find_last_of(L"/\\"));
}

std::string getPathDirectory(const std::string& path)
{
    // Returns the whole string if no backslash is present
    return path.substr(0, path.find_last_of("/\\"));
}

std::wstring getProgramPath()
{
    wchar_t buff[MAX_PATH] = {0};
    if (GetModuleFileNameW(NULL, buff, FILENAME_MAX) == 0)
    {
        LOG_ERROR("Error getting executable path!");
        return L"";
    }
    return buff;
}

std::wstring getProgramDirectory()
{
    return getPathDirectory(getProgramPath());
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

std::wstring getDllPath()
{
    // https://stackoverflow.com/questions/6924195/get-dll-path-at-runtime
    wchar_t DllPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW((HINSTANCE)&__ImageBase, DllPath, _countof(DllPath)) == 0)
    {
        LOG_ERROR("Error getting Pythia DLL path");
        return L"";
    }
    return DllPath;
}

#ifdef _WIN64
#define EMBEDDEDPYTHONPATH L"python-" PYTHON_VERSION "-embed-amd64"
#else
#define EMBEDDEDPYTHONPATH L"python-" PYTHON_VERSION "-embed-win32"
#endif

std::wstring getPythonPath()
{
    return getPathDirectory(getDllPath()) + L"\\" + EMBEDDEDPYTHONPATH;
}
