// python-poc.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "EmbeddedPython.h"
#include <regex>
#include "ModsLocation.h"

extern EmbeddedPython *python;
extern std::string pythonInitializationError;

extern "C"
{
    __declspec (dllexport) void __stdcall RVExtension(char *output, int outputSize, const char *input);
}

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
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
            size_t minSize = min((size_t)outputSize, toPrint.size() + 1);
            strncpy_s(output, minSize, toPrint.c_str(), _TRUNCATE);
        }
        python->leavePythonThread();
    }
    else
    {
        // Escape all quotes (") in the second argument. We don't care about performance
        // since this is going to happen rarely
        std::string escaped = std::regex_replace(pythonInitializationError, std::regex("\""), "\"\"");
        std::string toPrint = std::string("[\"e\", \"Python not initialised: ") + escaped + "\"]";
        size_t minSize = min((size_t)outputSize, toPrint.size() + 1);
        strncpy_s(output, outputSize, toPrint.c_str(), _TRUNCATE);
    }
}
