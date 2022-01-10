#pragma once

// Forward declarations
#include <Python.h>
#include <string>
#include "ModsLocation.h" // TODO: Remove me

class EmbeddedPython
{
public:
    EmbeddedPython();
    virtual ~EmbeddedPython();

    void initializeAdapter();
    void initModules(modules_t mods);
    void deinitialize();
    void reload();
    void execute(char *output, int outputSize, const char* input);
    void enterPythonThread();
    void leavePythonThread();

private:
    EmbeddedPython(const EmbeddedPython&) = delete;
    void operator=(const EmbeddedPython&) = delete;
    void preInitializeEmbeddedPython(std::wstring wpath);
    void libpythonWorkaround();
    void libpythonWorkaroundClose();

private:
    PyObject *pModule;
    PyObject *pFunc;
    PyThreadState *pThreadState;

    #ifndef _WIN32
    void* libpythonHandle = nullptr;
    #endif

    // Python magic
    std::wstring pythonHomeString;
    std::wstring programNameString;
};
