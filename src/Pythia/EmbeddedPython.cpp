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
#include "Paths.h"
#include "Modules/pythiainternal.h"
#include "Modules/pythialogger.h"

#define THROW_PYEXCEPTION(_msg_) throw std::runtime_error(_msg_ + std::string(": ") + PyExceptionFetcher().getError());
//#define EXTENSION_DEVELOPMENT 1

EmbeddedPython *python = nullptr;
std::string pythonInitializationError = "";
unsigned long multipartCounter = 0;
std::unordered_map<unsigned long long int, multipart_t> multiparts;

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

void EmbeddedPython::DoPythonMagic(std::wstring path)
{
    // Python pre-initialization magic
    LOG_INFO(std::string("Python version: ") + Py_GetVersion());

    // Clear the env variables, just in case
    _wputenv_s(L"PYTHONHOME", L"");
    _wputenv_s(L"PYTHONPATH", L"");
    _wputenv_s(L"PYTHONNOUSERSITE", L"1");  // Disable custom user site

    Py_IgnoreEnvironmentFlag = 1;
    Py_IsolatedFlag = 1;
    Py_NoSiteFlag = 1;
    Py_NoUserSiteDirectory = 1;

    // Py_SetPythonHome(L"D:\\Steam\\steamapps\\common\\Arma 3\\@Pythia\\python-embed-amd64");
    pythonHomeString = std::vector<wchar_t>(path.begin(), path.end());
    pythonHomeString.push_back(0);
    Py_SetPythonHome(pythonHomeString.data());
    LOG_INFO(std::string("Python home: ") + Logger::w2s(Py_GetPythonHome()));

    // Py_SetProgramName(L"D:\\Steam\\steamapps\\common\\Arma 3\\@Pythia\\python-embed-amd64\\python.exe");
    std::wstring programName = path + L"\\python.exe"; // Not sure if that should be the value here
    programNameString = std::vector<wchar_t>(programName.begin(), programName.end());
    programNameString.push_back(0);
    Py_SetProgramName(programNameString.data());
    LOG_INFO(std::string("Program name: ") + Logger::w2s(Py_GetProgramName()));

    /*
    Py_SetPath(L"D:\\Steam\\SteamApps\\common\\Arma 3\\@Pythia\\python-embed-amd64\\python35.zip;"
        L"D:\\Steam\\SteamApps\\common\\Arma 3\\@Pythia\\python-embed-amd64\\DLLs;"
        L"D:\\Steam\\SteamApps\\common\\Arma 3\\@Pythia\\python-embed-amd64\\lib;"
        L"D:\\Steam\\SteamApps\\common\\Arma 3\\@Pythia\\python-embed-amd64;"
        L"D:\\Steam\\SteamApps\\common\\Arma 3\\@Pythia\\python-embed-amd64\\Lib\\site-packages;"
        L"D:\\Steam\\SteamApps\\common\\Arma 3");
    */
    // TODO: Linux separator is ':'
    std::wstring allPaths =
        path + L"\\python" PYTHON_VERSION + L".zip" + L";" +
        path + L"\\DLLs" + L";" +
        path + L"\\lib" + L";" +
        path + L";" +
        path + L"\\Lib\\site-packages" + L";" +
        getProgramDirectory(); // For `python/` directory access. TODO: Use import hooks for that
    pathString = std::vector<wchar_t>(allPaths.begin(), allPaths.end());
    pathString.push_back(0);
    // Not setting PySetPath overwrites the Py_SetProgramName value (it seems to be ignored then),
    Py_SetPath(pathString.data());
    LOG_INFO(std::string("Python paths: ") + Logger::w2s(Py_GetPath()));
    LOG_INFO(std::string("Current directory: ") + GetCurrentWorkingDir());
}

EmbeddedPython::EmbeddedPython(HMODULE moduleHandle): dllModuleHandle(moduleHandle)
{
    DoPythonMagic(getPythonPath());
    PyImport_AppendInittab("pythiainternal", PyInit_pythiainternal);
    PyImport_AppendInittab("pythialogger", PyInit_pythialogger);
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
        LOG_ERROR(std::string("Caught error when reloading the extension: ") + ex.what());
        pythonInitializationError = ex.what();
    }
}

EmbeddedPython::~EmbeddedPython()
{
    enterPythonThread();
    deinitialize();
    Py_Finalize();
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
    snprintf(output, outputSize - 1, "[\"m\",%lu,%lu]", multipartCounter++, (unsigned long)entry.size());
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

    auto timeStart = std::chrono::high_resolution_clock::now();
    if (!pFunc)
    {
        LOG_ERROR("Calling function {}", input);
        throw std::runtime_error("No bootstrapping function. Additional error: " + pythonInitializationError);
    }

    PyObjectGuard pArgs(SQFReader::decode(input));
    auto timeDecodeEnded = std::chrono::high_resolution_clock::now();

    PyObjectGuard pTuple(PyTuple_Pack(1, pArgs.get()));
    if (!pTuple)
    {
        LOG_ERROR("Calling function {}", input);
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
                    // Do not log multipart requests for performance reasons
                    return;
                }
                else
                {
                    LOG_ERROR("Calling function {}", input);
                    throw std::runtime_error("Could not read the multipart ID");
                }
            }
            else
            {
                LOG_ERROR("Calling function {}", input);
                throw std::runtime_error("Could not get the multipart ID from the request");
            }
        }
    }
    else
    {
        LOG_ERROR("Calling function {}", input);
        throw std::runtime_error("Failed to get the function name from the request");
    }

    auto timeAfterMultipartCheck = std::chrono::high_resolution_clock::now();

    PyObjectGuard pResult(PyObject_CallObject(pFunc, pTuple.get()));
    auto timeAfterCall = std::chrono::high_resolution_clock::now();
    if (pResult)
    {
        MultipartResponseWriter writer(output, outputSize);
        writer.initialize();
        SQFWriter::encode(pResult.get(), &writer);
        writer.finalize();

        auto multipartResponse = writer.getMultipart();
        handleMultipart(output, outputSize, multipartResponse);
        auto timeEnd = std::chrono::high_resolution_clock::now();
        LOG_INFO(
            "Calling function {}(...). Total: {}us", //, Decoding: {}us, Call: {}us, Encoding: {}us, Multipart: {}us",
            PyUnicode_AsUTF8(PyFunction),
            (std::chrono::duration_cast<std::chrono::microseconds>(timeEnd - timeStart)).count()/*,
            (std::chrono::duration_cast<std::chrono::microseconds>(timeDecodeEnded - timeStart)).count(),
            (std::chrono::duration_cast<std::chrono::microseconds>(timeAfterCall - timeAfterMultipartCheck)).count(),
            (std::chrono::duration_cast<std::chrono::microseconds>(timeEnd - timeAfterCall)).count(),
            (std::chrono::duration_cast<std::chrono::microseconds>(timeAfterMultipartCheck - timeDecodeEnded)).count()*/
        );
        return;
    }
    else
    {
        LOG_ERROR("Calling function {}", input);
        THROW_PYEXCEPTION("Failed to execute python extension");
    }
}
