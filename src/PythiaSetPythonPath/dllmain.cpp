#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "../Pythia/Logger.h"
#include "../Pythia/Paths.h"
#include "../Pythia/common.h"

#define LOGGER_FILENAME LITERAL("PythiaSetPythonPath.log")

std::shared_ptr<spdlog::logger> Logger::logfile = nullptr;
tstring pythonPath = LITERAL("<Not set>");

void setDLLPath()
{
    LOG_INFO("Setting DLL path");
    pythonPath = getPythonPath();

    #ifdef _WIN32
    LOG_INFO(std::string("Setting DLL path to: ") + Logger::w2s(pythonPath));
    if (SetDllDirectory(pythonPath.c_str()) == 0)
    {
        LOG_ERROR("Failed to call SetDllDirectory");
    }
    #else
    LOG_INFO("Not changing any paths. On linux, this is handled using rpath in Pythia.so");
    #endif
}

class library
{
public:
    library()
    {
        Logger::logfile = getFallbackLogger();
        createLogger("PythiaSetPythonPathLogger", LOGGER_FILENAME);
        setDLLPath();
    }

    ~library()
    {
#ifdef _WIN32
        // On linux this seems to be called too late and causes a segfault
        LOG_FLUSH();
#endif // _WIN32

        spdlog::drop_all();
    }
};

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

void __stdcall RVExtensionVersion(char* output, int outputSize)
{
    static std::unique_ptr<library> libraryPtr = std::make_unique<library>();

    std::string versionInfo(PYTHIA_VERSION);
    size_t minSize = std::min<size_t>((size_t)outputSize, versionInfo.size() + 1);
    snprintf(output, minSize, "%s", versionInfo.c_str());
}

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
#ifdef _WIN32
    std::string str = Logger::w2s(pythonPath);
#else
    std::string str = pythonPath;
#endif
    size_t minSize = std::min<size_t>((size_t)outputSize, str.size() + 1);
    snprintf(output, minSize, "%s", str.c_str());
}

#ifdef _WIN32
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    return TRUE;
}
#endif
