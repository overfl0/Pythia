// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "../Pythia/Logger.h"
#include "../Pythia/Paths.h"
#include "../Pythia/common.h"

#define LOGGER_FILENAME LITERAL("PythiaSetPythonPath.log")

std::shared_ptr<spdlog::logger> Logger::logfile = getFallbackLogger();  // TODO: Changeme
std::wstring pythonPath = L"<Not set>";

void setDLLPath()
{
    LOG_INFO("Setting DLL path");
    tstring pythonPath = getPythonPath();

    #ifdef _WIN32
    LOG_INFO(std::string("Setting DLL path to: ") + Logger::w2s(pythonPath));
    if (SetDllDirectory(pythonPath.c_str()) == 0)
    {
        LOG_ERROR("Failed to call SetDllDirectory");
    }
    #else
    LOG_INFO("Not changing any paths, for now, on linux. #TODO");
    #endif
}

extern "C"
{
#ifdef _WIN32
    __declspec(dllexport) void __stdcall RVExtension(char* output, int outputSize, const char* input);
    __declspec(dllexport) void __stdcall RVExtensionVersion(char* output, int outputSize);
#else
#define __stdcall
    __attribute__((visibility("default"))) void RVExtension(char* output, int outputSize, const char* input);
    __attribute__((visibility("default"))) void RVExtensionVersion(char* output, int outputSize);
#endif
}

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
    std::string str = Logger::w2s(pythonPath);
    size_t minSize = std::min<size_t>((size_t)outputSize, str.size() + 1);
    snprintf(output, minSize, "%s", str.c_str());
}

void __stdcall RVExtensionVersion(char *output, int outputSize)
{
    std::string versionInfo(PYTHIA_VERSION);
    size_t minSize = std::min<size_t>((size_t)outputSize, versionInfo.size() + 1);
    snprintf(output, minSize, "%s", versionInfo.c_str());
}

#ifndef _WIN32
__attribute__((constructor))
#endif
void libraryLoad()
{
    createLogger("PythiaSetPythonPathLogger", LOGGER_FILENAME);
    setDLLPath();
    LOG_FLUSH();
}

#ifndef _WIN32
__attribute__((destructor))
#endif
void libraryUnload()
{
    LOG_FLUSH();
    spdlog::drop_all();
}

#ifdef _WIN32
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        libraryLoad();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        libraryUnload();
        break;
    }
    return TRUE;
}
#endif
