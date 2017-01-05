// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "DelayedLoader.h"
#include "EmbeddedPython.h"
#include "Logger.h"
#include <iostream>

extern EmbeddedPython *python;
extern std::string pythonInitializationError;

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            int retval = 0;

            // Ignore delay loading dlls for now as there are problems with loading
            // data from those dlls - and we need that data!
            /*
            if ((retval = LoadAllImports()) != 0)
            {
                std::string error_message = "Failed to load python35.dll "
                                            "(error: " + std::to_string(retval) + "). "
                                            "Ensure that Python 3.5 is correctly installed!";
                LOG_ERROR(error_message);
                pythonInitializationError = error_message;
                return TRUE;
            }
            */

            try
            {
                python = new EmbeddedPython(hModule);
                LOG_INFO("Python extension successfully loaded");
            }
            catch (const std::exception& ex)
            {
                LOG_ERROR("Caught error when creating the embedded python: " << ex.what());
                pythonInitializationError = ex.what();
            }
        }
        break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
        {
            if (python)
            {
                delete python;
                python = nullptr;
            }
        }
        break;
    }
    return TRUE;
}

