#include "stdafx.h"
#include <string>
#include "Logger.h"

#ifdef _WIN64
#define PYTHONPATH L"python-embed-amd64"
#else
#define PYTHONPATH L"python-embed-win32"
#endif

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

std::wstring getPythonPath()
{
    // https://stackoverflow.com/questions/6924195/get-dll-path-at-runtime
    WCHAR DllPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW((HINSTANCE)&__ImageBase, DllPath, _countof(DllPath)) == 0)
    {
        LOG_ERROR("Error getting Pythia DLL path");
        return L"";
    }
    std::wstring DllPath_s = DllPath;

    std::wstring directory;
    const size_t last_slash_idx = DllPath_s.rfind(L'\\');
    if (std::string::npos != last_slash_idx)
    {
        directory = DllPath_s.substr(0, last_slash_idx);
    }

    std::wstring pythonPath = directory + L"\\" + PYTHONPATH;
    return pythonPath;
}
