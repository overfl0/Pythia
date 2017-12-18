#include "stdafx.h"
#include "EmbeddedPython.h"
#include "ModsLocation.h"
#include "ExceptionFetcher.h"
#include "ResourceLoader.h"
#include <iostream>
#include "resource.h"
#include "Logger.h"
#include "ResponseWriter.h"
#include "SQFReader.h"
#include "SQFWriter.h"

#define THROW_PYEXCEPTION(_msg_) throw std::runtime_error(_msg_ + std::string(": ") + PyExceptionFetcher().getError());
//#define EXTENSION_DEVELOPMENT 1

EmbeddedPython *python = nullptr;
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
            if (ptr != nullptr)
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
            return ptr != nullptr;
        }

        /// Release ownership
        PyObject* transfer()
        {
            PyObject* tmp = ptr;
            ptr = nullptr;
            return tmp;
        }

    private:
        PyObjectGuard(const PyObjectGuard&) = delete;
        void operator=(const PyObjectGuard&) = delete;

    private:
        PyObject *ptr;
    };
}

EmbeddedPython::EmbeddedPython(HMODULE moduleHandle): dllModuleHandle(moduleHandle)
{
    Py_Initialize();
    PyEval_InitThreads(); // Initialize and acquire GIL
    initialize();
    leavePythonThread();
}

void EmbeddedPython::enterPythonThread()
{
    PyEval_RestoreThread(pThreadState);
}

void EmbeddedPython::leavePythonThread()
{
    pThreadState = PyEval_SaveThread();
}

void EmbeddedPython::initialize()
{
    #ifdef EXTENSION_DEVELOPMENT
    PyObjectGuard mainModuleName(PyUnicode_DecodeFSDefault("python.Adapter"));
    if (!mainModuleName)
    {
        THROW_PYEXCEPTION("Failed to create unicode module name");
    }

    PyObjectGuard moduleOriginal(PyImport_Import(mainModuleName.get()));
    if (!moduleOriginal)
    {
        THROW_PYEXCEPTION("Failed to import adapter module");
    }

    // Reload the module to force re-reading the file
    PyObjectGuard module(PyImport_ReloadModule(moduleOriginal.get()));
    if (!module)
    {
        THROW_PYEXCEPTION("Failed to reload adapter module");
    }

    #else

    std::string text_resource = ResourceLoader::loadTextResource(dllModuleHandle, PYTHON_ADAPTER, TEXT("PYTHON")).c_str();
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
    #endif

    PyObjectGuard function(PyObject_GetAttrString(module.get(), "python_adapter"));
    if (!function || !PyCallable_Check(function.get()))
    {
        THROW_PYEXCEPTION("Failed to reference python function 'python_adapter'");
    }

    pModule = module.transfer();
    pFunc = function.transfer();
}

void EmbeddedPython::initModules(modules_t mods)
{
    /**
    Initialize python sources for modules.
    The sources passed here will be used to import `pythia.modulename`.
    */

    if (!pModule)
    {
        THROW_PYEXCEPTION("Pythia adapter not loaded correctly. Not initializing python modules.")
    }

    PyObjectGuard pDict(PyDict_New());
    if (!pDict)
    {
        THROW_PYEXCEPTION("Could not create a new python dict.")
    }

    // Fill the dict with the items in the unordered_map
    for (const auto& entry: mods)
    {
        PyObjectGuard pString(PyUnicode_FromWideChar(entry.second.c_str(), -1));
        if (!pString)
        {
            continue;
        }

        int retval = PyDict_SetItemString(pDict.get(), entry.first.c_str(), pString.get());
        if (retval == -1)
        {
            THROW_PYEXCEPTION("Error while running PyDict_SetItemString.")
        }
    }

    // Perform the call adding the mods sources
    PyObjectGuard function(PyObject_GetAttrString(pModule, "init_modules"));
    if (!function || !PyCallable_Check(function.get()))
    {
        THROW_PYEXCEPTION("Failed to reference python function 'init_modules'");
    }

    PyObjectGuard pResult(PyObject_CallFunctionObjArgs(function.get(), pDict.get(), NULL));
    if (pResult)
    {
        return; // Yay!
    }
    else
    {
        THROW_PYEXCEPTION("Failed to execute python init_modules function");
    }
}

void EmbeddedPython::deinitialize()
{
    Py_CLEAR(pFunc);
    Py_CLEAR(pModule);
}

void EmbeddedPython::reload()
{
    deinitialize();
    try
    {
        initialize();
        LOG_INFO("Python extension successfully reloaded");
    }
    catch (const std::exception& ex)
    {
        LOG_ERROR("Caught error when reloading the extension: " << ex.what());
        pythonInitializationError = ex.what();
    }
}

EmbeddedPython::~EmbeddedPython()
{
    enterPythonThread();
    deinitialize();
    Py_Finalize();
}

unsigned long multipartCounter = 0;
std::unordered_map<unsigned long long int, multipart_t> multiparts;

std::vector<std::string> splitString(const std::string str, int splitLength)
{
    size_t NumSubstrings = str.length() / splitLength;
    std::vector<std::string> ret;

    for (size_t i = 0; i < NumSubstrings; i++)
    {
        ret.push_back(str.substr(i * splitLength, splitLength));
    }

    // If there are leftover characters, create a shorter item at the end.
    if (str.length() % splitLength != 0)
    {
        ret.push_back(str.substr(splitLength * NumSubstrings));
    }

    return ret;
}

// Note: outputSize is the size CONTAINING the null terminator
void handleMultipart(char *output, int outputSize, multipart_t entry)
{
    if (entry.empty())
    {
        return;
    }

    multiparts[multipartCounter] = entry;

    //["m", MULTIPART_COUNTER, len(responses)]
    snprintf(output, outputSize - 1, "[\"m\", %lu, %lu]", multipartCounter++, (unsigned long)entry.size());
}

// Note: outputSize is the size CONTAINING the null terminator
void returnMultipart(unsigned long multipartID, char *output, int outputSize)
{
    try
    {
        auto &entry = multiparts.at(multipartID);
        auto &retval = entry.front();

        size_t minSize = min((size_t)outputSize, retval.size() + 1);
        strncpy_s(output, minSize, retval.data(), _TRUNCATE);

        entry.pop();
        if (entry.empty())
        {
            multiparts.erase(multipartID);
        }
    }
    catch (std::out_of_range)
    {
        output[0] = '\0';
    }
}

// Note: outputSize is the size CONTAINING the null terminator
// A value of 10240 means that you can have 10239 characters + '\0' there
void EmbeddedPython::execute(char *output, int outputSize, const char *input)
{
    #ifdef EXTENSION_DEVELOPMENT
        reload();
    #endif

    if (!pFunc)
    {
        throw std::runtime_error("No bootstrapping function. Additional error: " + pythonInitializationError);
    }

    PyObjectGuard pArgs(SQFReader::decode(input));

    /*PyObjectGuard pArgs(PyUnicode_FromString(input));
    if (!pArgs)
    {
        throw std::runtime_error("Failed to transform given input to unicode");
    }*/

    PyObjectGuard pTuple(PyTuple_Pack(1, pArgs.get()));
    if (!pTuple)
    {
        throw std::runtime_error("Failed to convert argument string to tuple");
    }

    PyObject* PyFunction = PyList_GetItem(pArgs.get(), 0); // Borrows reference
    if (PyFunction)
    {
        // Multipart
        // TODO: Do a Python string comparison
        if (PyUnicode_CompareWithASCIIString(PyFunction, "pythia.multipart") == 0)
        {
            PyObject* PyMultipartID = PyList_GetItem(pArgs.get(), 1); // Borrows reference
            if (PyMultipartID)
            {
                int overflow;
                long multipartID = PyLong_AsLongAndOverflow(PyMultipartID, &overflow);
                if (overflow == 0 && multipartID >= 0)
                {
                    returnMultipart(multipartID, output, outputSize);
                    return;
                }
                else
                {
                    throw std::runtime_error("Could not read the multipart ID");
                }
            }
            else
            {
                throw std::runtime_error("Could not get the multipart ID from the request");
            }
        }
    }
    else
    {
        throw std::runtime_error("Failed to get the function name from the request");
    }

    PyObjectGuard pResult(PyObject_CallObject(pFunc, pTuple.get()));
    if (pResult)
    {
        MultipartResponseWriter writer(output, outputSize);
        writer.initialize();
        SQFWriter::encode(pResult.get(), &writer);
        writer.finalize();

        auto multipartResponse = writer.getMultipart();
        handleMultipart(output, outputSize, multipartResponse);
        return;
    }
    else
    {
        THROW_PYEXCEPTION("Failed to execute python extension");
    }
}

