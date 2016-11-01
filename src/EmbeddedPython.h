#pragma once

// Forward declarations
#include <Python.h>
#include <string>

class EmbeddedPython
{
public:
    EmbeddedPython(HMODULE moduleHandle);
    virtual ~EmbeddedPython();
    
    void initialize();
    void deinitialize();
    void reload();
    std::string execute(const char* input);

private:
    EmbeddedPython(const EmbeddedPython&) = delete;
    void operator=(const EmbeddedPython&) = delete;

private:
    PyObject *pModule;
    PyObject *pFunc;
    HMODULE dllModuleHandle;
};

