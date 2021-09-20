// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "DelayedLoader.h"
#include "EmbeddedPython.h"
#include "Logger.h"
#include <iostream>

extern EmbeddedPython *python;
extern std::string pythonInitializationError;

std::shared_ptr<spdlog::logger> Logger::logfile = getFallbackLogger();

#ifndef _WIN32
__attribute__((constructor))
#endif
void libraryLoad()
{
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


#ifndef _WIN32
__attribute__((destructor))
#endif
void libraryUnload()
{
    if (python)
    {
        delete python;
        python = nullptr;
    }
    //LOG_FLUSH();
    spdlog::drop_all();
}

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule,
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
