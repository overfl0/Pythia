// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h> 
#include <tchar.h>
#include <string>

#ifdef _WIN64
#define PYTHONPATH L"python-embed-amd64"
#else
#define PYTHONPATH L"python-embed-win32"
#endif

EXTERN_C IMAGE_DOS_HEADER __ImageBase;


std::wstring pythonPath = L"<Not set>";

void setDLLPath()
{
    // https://stackoverflow.com/questions/6924195/get-dll-path-at-runtime

    WCHAR   DllPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW((HINSTANCE)&__ImageBase, DllPath, _countof(DllPath)) == 0)
    {
        // TODO: Error checking
        int a = 5;
    }
    std::wstring DllPath_s = DllPath;

    std::wstring directory;
    const size_t last_slash_idx = DllPath_s.rfind(L'\\');
    if (std::string::npos != last_slash_idx)
    {
        directory = DllPath_s.substr(0, last_slash_idx);
    }

    pythonPath = directory + L"\\" + PYTHONPATH;
    if (SetDllDirectory(pythonPath.c_str()) == 0)
    {
        // TODO: Error checking
        int b = 6;
    }

    _wputenv_s(L"PYTHONHOME", pythonPath.c_str());
}

extern "C"
{
    __declspec (dllexport) void __stdcall RVExtension(char *output, int outputSize, const char *input);
}

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
    std::string str(pythonPath.begin(), pythonPath.end());
    strncpy_s(output, outputSize, str.c_str(), _TRUNCATE);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
        setDLLPath();
        break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

