#include "stdafx.h"
#include "EmbeddedPython.h"
#include "ResourceLoader.h"
#include <iostream>
#include "resource.h"
#include "Logger.h"

#define THROW_PYEXCEPTION(_msg_) throw std::runtime_error(_msg_ + std::string(": ") + PyExceptionFetcher().getError());

EmbeddedPython *python = NULL;
std::string pythonInitializationError = "";

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
            pValueRepr = NULL;
        }

        ~PyExceptionFetcher()
        {
            PyErr_Restore(pType, pValue, pTraceback);
            Py_XDECREF(pValueRepr);
        }

        std::string getError(int recursion = 0)
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

    private:
        PyExceptionFetcher(const PyExceptionFetcher&) = delete;
        void operator=(const PyExceptionFetcher&) = delete;

    private:
        PyObject *pType, *pValue, *pTraceback;
        PyObject *pValueRepr;
    };
}

EmbeddedPython::EmbeddedPython(HMODULE moduleHandle)
{
    Py_Initialize();

    std::string text_resource = ResourceLoader::loadTextResource(moduleHandle, PYTHON_ADAPTER, TEXT("PYTHON")).c_str();
    PyObject *compiledString = Py_CompileString(
        text_resource.c_str(),
        "python-adapter.py",
        Py_file_input);

    PyObjectGuard pCompiledContents(compiledString);
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
        throw std::runtime_error("Python extension not initialised.");
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


