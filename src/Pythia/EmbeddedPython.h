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
    void execute(char *output, int outputSize, const char* input);
    void enterPythonThread();
    void leavePythonThread();

private:
    EmbeddedPython(const EmbeddedPython&) = delete;
    void operator=(const EmbeddedPython&) = delete;
    void DoPythonMagic(std::wstring path);

private:
    PyObject *pModule;
    PyObject *pFunc;
    PyThreadState *pThreadState;
    HMODULE dllModuleHandle;

    // Python magic
    std::vector<wchar_t> pythonHomeString;
    std::vector<wchar_t> programNameString;
    std::vector<wchar_t> pathString;
};

