// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h> 
#include <tchar.h>
#include <string>
#include <locale> // wstring_convert
#define LOGGER_FILENAME "PythiaSetPythonPath.log"
#include "../src/Logger.h"
#include "../src/PythonPath.h"
#include "../src/common.h"

std::wstring pythonPath = L"<Not set>";

std::string w2s(const std::wstring &var)
{
    static std::locale loc("");
    auto &facet = std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t>>(loc);
    return std::wstring_convert<std::remove_reference<decltype(facet)>::type, wchar_t>(&facet).to_bytes(var);
}

std::wstring s2w(const std::string &var)
{
    static std::locale loc("");
    auto &facet = std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t>>(loc);
    return std::wstring_convert<std::remove_reference<decltype(facet)>::type, wchar_t>(&facet).from_bytes(var);
}

void setDLLPath()
{
    LOG_INFO("Setting DLL path");
    std::wstring pythonPath = getPythonPath();

    LOG_INFO(std::string("Setting DLL path to: ") + w2s(pythonPath));
    if (SetDllDirectory(pythonPath.c_str()) == 0)
    {
        LOG_ERROR("Failed to call SetDllDirectory");
    }
}

extern "C"
{
    __declspec (dllexport) void __stdcall RVExtension(char *output, int outputSize, const char *input);
    __declspec (dllexport) void __stdcall RVExtensionVersion(char *output, int outputSize);
}

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
    std::string str(pythonPath.begin(), pythonPath.end());
    size_t minSize = min((size_t)outputSize, str.size() + 1);
    strncpy_s(output, minSize, str.c_str(), _TRUNCATE);
}

void __stdcall RVExtensionVersion(char *output, int outputSize)
{
    std::string versionInfo(PYTHIA_VERSION);
    size_t minSize = min((size_t)outputSize, versionInfo.size() + 1);
    strncpy_s(output, minSize, versionInfo.c_str(), _TRUNCATE);
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

