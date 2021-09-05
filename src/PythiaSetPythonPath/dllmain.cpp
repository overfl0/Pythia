// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h> 
#include <tchar.h>
#include <string>
#include "../Pythia/Logger.h"
#include "../Pythia/Paths.h"
#include "../Pythia/common.h"

#define LOGGER_FILENAME L"PythiaSetPythonPath.log"

std::shared_ptr<spdlog::logger> Logger::logfile = getFallbackLogger();
std::wstring pythonPath = L"<Not set>";

void setDLLPath()
{
    LOG_INFO("Setting DLL path");
    std::wstring pythonPath = getPythonPath();

    LOG_INFO(std::string("Setting DLL path to: ") + Logger::w2s(pythonPath));
    if (SetDllDirectory(pythonPath.c_str()) == 0)
    {
        LOG_ERROR("Failed to call SetDllDirectory");
    }
}

extern "C"
{
    __declspec (dllexport) void __stdcall RVExtension(char *output, int outputSize, const char *input);
    __declspec (dllexport) void __stdcall RVExtensionVersion(char *output, int outputSize);
}

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
    std::string str = Logger::w2s(pythonPath);
    size_t minSize = min((size_t)outputSize, str.size() + 1);
    strncpy_s(output, minSize, str.c_str(), _TRUNCATE);
}

void __stdcall RVExtensionVersion(char *output, int outputSize)
{
    std::string versionInfo(PYTHIA_VERSION);
    size_t minSize = min((size_t)outputSize, versionInfo.size() + 1);
    strncpy_s(output, minSize, versionInfo.c_str(), _TRUNCATE);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        createLogger("PythiaSetPythonPathLogger", LOGGER_FILENAME);
        setDLLPath();
        LOG_FLUSH();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        LOG_FLUSH();
        spdlog::drop_all();
        break;
    }
    return TRUE;
}
