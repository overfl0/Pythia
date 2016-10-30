// python-poc.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "EmbeddedPython.h"

extern EmbeddedPython *python;

extern "C"
{
    __declspec (dllexport) void __stdcall RVExtension(char *output, int outputSize, const char *input);
}

void __stdcall RVExtension(char *output, int outputSize, const char *input)
{
	outputSize -= 1;
	output[outputSize] = '\0';

    if (python != NULL)
    {
        try
        {
            strncpy_s(output, outputSize, python->execute(input).c_str(), _TRUNCATE);
        }
        catch (const std::exception& ex)
        {
            strncpy_s(output, outputSize, (std::string("e:") + ex.what()).c_str(), _TRUNCATE);
        }
    }
    else
    {
        strncpy_s(output, outputSize, "e:python not initialised", _TRUNCATE);
    }
}
