#include "stdafx.h"

#include "ExceptionFetcher.h"


PyExceptionFetcher::PyExceptionFetcher()
{
    PyErr_Fetch(&pType, &pValue, &pTraceback);
    pValueRepr = nullptr;
}

PyExceptionFetcher::~PyExceptionFetcher()
{
    PyErr_Restore(pType, pValue, pTraceback);
    Py_XDECREF(pValueRepr);
}

std::string PyExceptionFetcher::getError(int recursion)
{
    if (!pValue)
    {
        return "";
    }

    if (recursion > 2)
    {
        return "getError: Maximum recursion limit reached!";
    }

    char *value_utf8 = PyUnicode_AsUTF8(pValue);
    if (value_utf8)
    {
        return value_utf8;
    }

    // Could not encode pValue as a UTF-8 string. Let's try its repr()
    // Note: PyObject_Repr will produce an error if the error indicator is set.
    // We need to clear the error indicator for the time of the repr() call.
    {
        PyObject *_pType, *_pValue, *_pTraceback;
        PyErr_Fetch(&_pType, &_pValue, &_pTraceback);
        PyErr_Clear();
        pValueRepr = PyObject_Repr(pValue);
        PyErr_Restore(_pType, _pValue, _pTraceback);
    }

    if (pValueRepr)
    {
        value_utf8 = PyUnicode_AsUTF8(pValueRepr);
        if (value_utf8)
        {
            return value_utf8;
        }
    }

    // Still an error? Let's return the exception
    std::string error_message = "Exception while getting error: " +
        PyExceptionFetcher().getError(recursion + 1);

    return error_message;
}
