// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include "EmbeddedPython.h"

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
		python = new EmbeddedPython();
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

