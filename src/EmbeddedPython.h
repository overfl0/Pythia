#pragma once

// Forward declarations
#include <Python.h>
#include <string>
#include "ModsLocation.h" // TODO: Remove me

class EmbeddedPython
{
public:
    EmbeddedPython(HMODULE moduleHandle);
    virtual ~EmbeddedPython();
    
    void initialize();
    void initModules(modules_t mods);
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

