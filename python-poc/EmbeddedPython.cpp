#include "stdafx.h"
#include "EmbeddedPython.h"
#include "ResourceLoader.h"
#include <iostream>
#include "resource.h"
#include "Logger.h"

#define THROW_PYEXCEPTION(_msg_) throw std::runtime_error(_msg_ + std::string(": ") + PyExceptionFetcher().getError());

EmbeddedPython *python = NULL;

namespace
{
    class PyObjectGuard final
    {
    public:
        PyObjectGuard(PyObject* source) : ptr(source)
        {
        }

        ~PyObjectGuard()
        {
            if (ptr != NULL)
            {
                Py_DECREF(ptr);
            }
        }

        PyObject* get() const
        {
            return ptr;
        }

        explicit operator bool() const
        {
            return ptr != NULL;
        }

        /// Release ownership
        PyObject* transfer()
        {
            PyObject* tmp = ptr;
            ptr = NULL;
            return tmp;
        }

    private:
        PyObjectGuard(const PyObjectGuard&) = delete;
        void operator=(const PyObjectGuard&) = delete;

    private:
        PyObject *ptr;
    };

    class PyExceptionFetcher final
    {
    public:
        PyExceptionFetcher()
        {
            PyErr_Fetch(&pType, &pValue, &pTraceback);
        }

        ~PyExceptionFetcher()
        {
            PyErr_Restore(pType, pValue, pTraceback);
        }

        std::string getError()
        {
            return (pValue != NULL ? PyUnicode_AsUTF8(pValue) : "");
        }

    private:
        PyExceptionFetcher(const PyExceptionFetcher&) = delete;
        void operator=(const PyExceptionFetcher&) = delete;

    private:
        PyObject *pType, *pValue, *pTraceback;
    };
}

EmbeddedPython::EmbeddedPython(HMODULE moduleHandle)
{
    Py_Initialize();

    PyObjectGuard pCompiledContents(Py_CompileString(
        ResourceLoader::loadTextResource(moduleHandle, PYTHON_ADAPTER, TEXT("PYTHON")).c_str(),
        "python-adapter.py",
        Py_file_input));

    if (!pCompiledContents)
    {
        THROW_PYEXCEPTION("Failed to compile embedded python module");
    }

    PyObjectGuard module(PyImport_ExecCodeModule("adapter", pCompiledContents.get()));
    if (!module)
    {
        THROW_PYEXCEPTION("Failed to add compiled module");
    }

    PyObjectGuard function(PyObject_GetAttrString(module.get(), "python_adapter"));
    if (!function || !PyCallable_Check(function.get()))
    {
        THROW_PYEXCEPTION("Failed to reference python function 'python_adapter'");
    }

    pModule = module.transfer();
    pFunc = function.transfer();
}

EmbeddedPython::~EmbeddedPython()
{
    Py_XDECREF(pFunc);
    Py_XDECREF(pModule);

    Py_Finalize();
}

std::string EmbeddedPython::execute(const char * input)
{
    if (!pFunc)
    {
        throw std::runtime_error("Python extension not initialised");
    }

    PyObjectGuard pArgs(PyUnicode_FromString(input));
    if (!pArgs)
    {
        throw std::runtime_error("Failed to transform given input to unicode");
    }

    PyObjectGuard pTuple(PyTuple_Pack(1, pArgs.get()));
    if (!pTuple)
    {
        throw std::runtime_error("Failed to convert argument string to tuple");
    }

    PyObjectGuard pResult(PyObject_CallObject(pFunc, pTuple.get()));
    if (pResult)
    {
        // Hopefully RVO applies here
        return std::string(PyUnicode_AsUTF8(pResult.get()));
    }
    else
    {
        THROW_PYEXCEPTION("Failed to execute python extension");
    }
}


