#pragma once

// Forward declarations
#include <Python.h>
#include <string>

class EmbeddedPython
{
public:
    EmbeddedPython(HMODULE moduleHandle);
    virtual ~EmbeddedPython();
    
    std::string execute(const char* input);

private:
    EmbeddedPython(const EmbeddedPython&) = delete;
    void operator=(const EmbeddedPython&) = delete;

private:
    PyObject *pModule;
    PyObject *pFunc;
};

