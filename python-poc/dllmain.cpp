// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "EmbeddedPython.h"
#include "Logger.h"
#include <iostream>

extern EmbeddedPython *python;

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
                python = new EmbeddedPython(hModule);
                LOG_INFO("Python extension successfully loaded");
            }
            catch (const std::exception& ex)
            {
                LOG_ERROR("Caught error when creating the embedded python: " << ex.what());
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
            }
        }
        break;
    }
    return TRUE;
}

