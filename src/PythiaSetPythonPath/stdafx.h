#pragma once

#ifdef _WIN32
#include <SDKDDKVer.h>

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

#define tstring std::wstring
#define WidenHelper(x)  L##x
#define LITERAL(x) WidenHelper(x)

#else // ifdef _WIN32

#define tstring std::string
#define LITERAL(x) (x)

#endif

/* Don't let Python.h #define (v)snprintf as macro because they are implemented
   properly in Visual Studio since 2015. */
#if defined(_MSC_VER) && _MSC_VER >= 1900
#  define HAVE_SNPRINTF 1
#endif
