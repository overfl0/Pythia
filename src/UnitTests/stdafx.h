#pragma once

/* Don't let Python.h #define (v)snprintf as macro because they are implemented
   properly in Visual Studio since 2015. */
#if defined(_MSC_VER) && _MSC_VER >= 1900
#  define HAVE_SNPRINTF 1
#endif

#include <SDKDDKVer.h>

// Headers for CppUnitTest
#include "CppUnitTest.h"

#include <string>
