#include "DelayedLoader.h"
#include "stdafx.h"
#include "Logger.h"
#ifdef _WIN32
#include <delayimp.h>
#endif

extern std::string pythonInitializationError;

#ifdef _WIN32
static DWORD DelayLoadExceptionFilter(DWORD code, int *error)
{
    if (code == VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND))
    {
        *error = ERROR_MOD_NOT_FOUND;
        return EXCEPTION_EXECUTE_HANDLER;
    }

    if (code == VcppException(ERROR_SEVERITY_ERROR, ERROR_PROC_NOT_FOUND))
    {
        *error = ERROR_PROC_NOT_FOUND;
        return EXCEPTION_EXECUTE_HANDLER;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

int LoadAllImports()
{
    // Load the delay-loaded python dll
    // This is done here to have full control over loading python.dll
    // and being able to return an error message in case of a load failure.

    int retval = 0;

#if 0
// We're not delay-loading for the time being
    #error This part of the code has NOT been tested with python > 3.5. You're running this code at your own risk!
    #ifndef NDEBUG
        // In debug builds we don't delay-load python35_d.dll because it contains data
        // and thus cannot be delay-loaded so we just load it automatically and this
        // function is not needed.
        return retval;
    #endif

    __try
    {
        retval = __HrLoadAllImportsForDll("python" PYTHON_VERSION ".dll");
        if (FAILED(retval))
        {
            return retval;
        }
    }
    __except (DelayLoadExceptionFilter(GetExceptionCode(), &retval))
    {
    }
#endif
    return retval;
}
