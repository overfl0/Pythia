#pragma once

#ifdef _WIN32
#include <SDKDDKVer.h>

//#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#endif

/* Don't let Python.h #define (v)snprintf as macro because they are implemented
   properly in Visual Studio since 2015. */
#if defined(_MSC_VER) && _MSC_VER >= 1900
#  define HAVE_SNPRINTF 1
#endif

#include <queue>
#include <random>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include "third_party/spdlog/spdlog.h"
