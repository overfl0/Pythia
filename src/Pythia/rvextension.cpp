// python-poc.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "EmbeddedPython.h"
#include <regex>
#include "ModsLocation.h"
#include "common.h"
#include "Logger.h"

extern EmbeddedPython *python;
extern std::string pythonInitializationError;

std::shared_ptr<spdlog::logger> Logger::logfile = nullptr;

class library
{
public:
    library()
    {
        Logger::logfile = getFallbackLogger();
        // Ignore delay loading dlls for now as there are problems with loading
        // data from those dlls - and we need that data!
        /*
        int retval = 0;
        if ((retval = LoadAllImports()) != 0)
        {
            std::string error_message = "Failed to load python" PYTHON_VERSION ".dll "
                                        "(error: " + std::to_string(retval) + "). "
                                        "Ensure that Python " PYTHON_VERSION_DOTTED " is correctly installed!";
            LOG_ERROR(error_message);
            pythonInitializationError = error_message;
            return TRUE;
        }
        */
        createLogger("PythiaLogger", LITERAL("Pythia_c.log"));

        try
        {
            python = new EmbeddedPython();
            LOG_INFO("Python extension successfully loaded");
        }
        catch (const std::exception& ex)
        {
            LOG_ERROR(std::string("Caught error when creating the embedded python: ") + ex.what());
            pythonInitializationError = ex.what();
        }
    }

    ~library()
    {
        if (python)
        {
            delete python;
            python = nullptr;
        }
        //LOG_FLUSH();
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

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
    static bool logger_initialized = false;
    if (!logger_initialized)
    {
        switchToAsyncLogger("PythiaLogger", LITERAL("Pythia_c.log"));
        logger_initialized = true;
    }
    if (python != nullptr)
    {
        python->enterPythonThread();
        try
        {
            static bool sources_initialized = false;
            if (!sources_initialized)
            {
                auto sources = getPythiaModulesSources();
                python->initModules(sources);
                sources_initialized = true;
            }

            python->execute(output, outputSize, input);
        }
        catch (const std::exception& ex)
        {
            // Escape all quotes (") in the second argument. We don't care about performance
            // since this is going to happen rarely
            std::string escaped = std::regex_replace(ex.what(), std::regex("\""), "\"\"");
            std::string toPrint = std::string("[\"e\", \"") + escaped + "\"]";
            size_t minSize = std::min<size_t>((size_t)outputSize, toPrint.size() + 1);
            snprintf(output, minSize, "%s", toPrint.c_str());
            LOG_ERROR(toPrint);
        }
        python->leavePythonThread();
    }
    else
    {
        // Escape all quotes (") in the second argument. We don't care about performance
        // since this is going to happen rarely
        std::string escaped = std::regex_replace(pythonInitializationError, std::regex("\""), "\"\"");
        std::string toPrint = std::string("[\"e\", \"Python not initialised: ") + escaped + "\"]";
        size_t minSize = std::min<size_t>((size_t)outputSize, toPrint.size() + 1);
        snprintf(output, minSize, "%s", toPrint.c_str());
        LOG_ERROR(toPrint);
    }
}

void __stdcall RVExtensionVersion(char *output, int outputSize)
{
    static std::unique_ptr<library> libraryPtr = std::make_unique<library>();

    std::string versionInfo(PYTHIA_VERSION);
    size_t minSize = std::min<size_t>((size_t)outputSize, versionInfo.size() + 1);
    snprintf(output, minSize, "%s", versionInfo.c_str());
}

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    return TRUE;
}
#endif
