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
    outputSize -= 1;
    output[outputSize] = '\0';

    if (python != nullptr)
    {
        try
        {
            //getDirectories();
            static bool sources_initialized = false;
            if (!sources_initialized)
            {
                auto sources = getPythiaModulesSources();
                python->initModules(sources);
                sources_initialized = true;
            }

            strncpy_s(output, outputSize, python->execute(input).c_str(), _TRUNCATE);
        }
        catch (const std::exception& ex)
        {
            // Escape all quotes (") in the second argument. We don't care about performance
            // since this is going to happen rarely
            std::string escaped = std::regex_replace(ex.what(), std::regex("\""), "\"\"");
            strncpy_s(output, outputSize, (std::string("[\"e\", \"") + escaped + "\"]").c_str(), _TRUNCATE);
        }
    }
    else
    {
        // Escape all quotes (") in the second argument. We don't care about performance
        // since this is going to happen rarely
        std::string escaped = std::regex_replace(pythonInitializationError, std::regex("\""), "\"\"");
        strncpy_s(output, outputSize, (std::string("[\"e\", \"Python not initialised: ") + escaped + "\"]").c_str(), _TRUNCATE);
    }
}
