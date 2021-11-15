#include "stdafx.h"
#include <string>
#include <filesystem>
#include "Logger.h"

#ifdef _WIN32
    #ifdef _WIN64
    #define EMBEDDEDPYTHONPATH L"python-" PYTHON_VERSION "-embed-amd64"
    #else
    #define EMBEDDEDPYTHONPATH L"python-" PYTHON_VERSION "-embed-win32"
    #endif
#else // ifdef _WIN32
    #if defined(__amd64__) || defined(_M_X64) /* x86_64 arch */
    #define EMBEDDEDPYTHONPATH "python-" PYTHON_VERSION "-embed-linux64"
    #else
    #define EMBEDDEDPYTHONPATH "python-" PYTHON_VERSION "-embed-linux32"
    #endif
#endif

std::string GetCurrentWorkingDir()
{
    std::error_code ec;
    const auto current_path = std::filesystem::current_path(ec);
    if (ec)
    {
        LOG_ERROR("Error getting current working directory!");
        return "";
    }

    return current_path.string();
}

#ifdef _WIN32
#include <direct.h>

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
    wchar_t buff[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, buff, FILENAME_MAX) == 0)
    {
        LOG_ERROR("Error getting executable path!");
        return L"";
    }
    return buff;
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

std::wstring getPythonPath()
{
    return getPathDirectory(getDllPath()) + L"\\" + EMBEDDEDPYTHONPATH;
}

#else

#include <unistd.h>
#include <dlfcn.h>

std::string getPathDirectory(const std::string& path)
{
    // Returns the whole string if no backslash is present
    return path.substr(0, path.find_last_of("/"));
}

std::string getProgramPath()
{
    std::error_code ec;
    auto selfPath = std::filesystem::path("/proc/self/exe");
    auto isSymlink = std::filesystem::is_symlink(selfPath, ec);
    if (!isSymlink)
    {
        LOG_ERROR("Error getting executable path! (/proc/self/exe is not a symlink)");
        return "";
    }

    auto self = std::filesystem::read_symlink(selfPath, ec);
    if (ec)
    {
        LOG_ERROR("Error getting executable path! (" + ec.message() + ")");
        return "";
    }

    return self;
}

std::string getSoPath()
{
    // Link with -ldl
    Dl_info dlInfo;
    bool success = dladdr((void*)getSoPath, &dlInfo);

    if (!success)
    {
        LOG_ERROR("Error getting Pythia .so path (dladdr failed)");
        return "";
    }

    if (dlInfo.dli_sname != NULL && dlInfo.dli_saddr != NULL)
        return dlInfo.dli_fname;
    else
    {
        LOG_ERROR("Error getting Pythia .so path (dlInfo.dli_sname == NULL or dlInfo.dli_saddr == NULL)");
        return "";
    }
}

std::string getPythonPath()
{
    return getPathDirectory(getSoPath()) + "/" + EMBEDDEDPYTHONPATH;
}
#endif

tstring getProgramDirectory()
{
    return getPathDirectory(getProgramPath());
}
