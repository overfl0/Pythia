#pragma once
#include "stdafx.h"

class PyExceptionFetcher final
{
public:
    PyExceptionFetcher();
    ~PyExceptionFetcher();
    std::string getError(int recursion = 0);

private:
    PyExceptionFetcher(const PyExceptionFetcher&) = delete;
    void operator=(const PyExceptionFetcher&) = delete;

private:
    PyObject *pType, *pValue, *pTraceback;
    PyObject *pValueRepr;
};
