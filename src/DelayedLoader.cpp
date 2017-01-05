#include "DelayedLoader.h"
#include "stdafx.h"
#include "Logger.h"
#include <delayimp.h>

extern std::string pythonInitializationError;

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

int LoadAllImports()
{
    // Load the delay-loaded python dll
    // This is done here to have full control over loading python.dll
    // and being able to return an error message in case of a load failure.

    int retval = 0;

#if 0
// We're not delay-loading for the time being
    #ifndef NDEBUG
        // In debug builds we don't delay-load python35_d.dll because it contains data
        // and thus cannot be delay-loaded so we just load it automatically and this
        // function is not needed.
        return retval;
    #endif

    __try
    {
        retval = __HrLoadAllImportsForDll("python35.dll");
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
