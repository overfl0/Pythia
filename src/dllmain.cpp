// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "DelayedLoader.h"
#include "EmbeddedPython.h"
#include "Logger.h"
#include <iostream>

extern EmbeddedPython *python;
extern std::string pythonInitializationError;

std::shared_ptr<spdlog::logger> Logger::logfile = spdlog::stderr_logger_mt("Dummy_stderr");

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            try
            {
                //spdlog::set_async_mode(4096);
                Logger::logfile = spdlog::rotating_logger_mt("PythiaLogger", "pythia_c.log", 1024 * 1024 * 5, 3);
            }
            catch (const spdlog::spdlog_ex& ex)
            {
                LOG_ERROR(std::string("Could not create the logfile!") + ex.what());
            }

            // Ignore delay loading dlls for now as there are problems with loading
            // data from those dlls - and we need that data!
            /*
            int retval = 0;
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
                LOG_ERROR(std::string("Caught error when creating the embedded python: ") + ex.what());
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
            Logger::logfile->flush();
            spdlog::drop_all();
        }
        break;
    }
    return TRUE;
}

