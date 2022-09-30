#include "stdafx.h"
#include "EmbeddedPython.h"
#include "ModsLocation.h"
#include "ExceptionFetcher.h"
#include "ResourceLoader.h"
#include <iostream>
#include "Logger.h"
#include "ResponseWriter.h"
#include "SQFReader.h"
#include "SQFWriter.h"
#include "Paths.h"
#include "Modules/pythiainternal.h"
#include "Modules/pythialogger.h"
#include "common.h"

#ifndef _WIN32
#include <dlfcn.h>
#endif

#define THROW_PYINITIALIZE_EXCEPTION(_msg_) throw std::runtime_error((_msg_));
#define THROW_PYEXCEPTION(_msg_) throw std::runtime_error((_msg_) + std::string(": ") + PyExceptionFetcher().getError());

EmbeddedPython *python = nullptr;
std::string pythonInitializationError;
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

std::wstring joinPaths(std::vector<std::wstring> const paths)
{
    std::wstring out;
    bool firstTime = true;
    for(const auto& path : paths)
    {
        if(firstTime)
        {
            firstTime = false;
            out += path;
        }
        else
        {
            #ifdef _WIN32
                out += L";";
            #else
                out += L":";
            #endif
            out += path;
        }
    }
    return out;
}

void EmbeddedPython::libpythonWorkaround()
{
    #ifndef _WIN32
        // https://stackoverflow.com/a/60746446/6543759
        // https://docs.python.org/3/whatsnew/3.8.html#changes-in-the-c-api
        // undefined symbol: PyExc_ImportError
        // Manually load libpythonX.Y.so with dlopen(RTLD_GLOBAL) to allow numpy to access python symbols
        // and in Python 3.8+ any C extension
        const char* pythonLibraryName = "libpython" PYTHON_VERSION_DOTTED ".so.1.0";

        libpythonHandle = dlopen(pythonLibraryName, RTLD_LAZY | RTLD_GLOBAL);
        if (!libpythonHandle)
        {
            LOG_INFO(std::string("Could not load ") + pythonLibraryName);
        }
    #endif // ifndef _WIN32
}

void EmbeddedPython::libpythonWorkaroundClose()
{
    #ifndef _WIN32
        if (libpythonHandle)
        {
            dlclose(libpythonHandle);
            libpythonHandle = nullptr;
        }
    #endif // ifndef _WIN32
}

std::vector<std::wstring> computePythonPaths(const std::wstring& wpath)
{
/*

# Obtain the current paths by running the embedded python binary
import sys
base_dir = sys.executable.split('/bin/')[0]
for path in sys.path:
    print(path.replace(base_dir, ''))

*/
    #ifdef _WIN32
        std::vector<std::wstring> allPaths({
            wpath + L"\\python" PYTHON_VERSION + L".zip",
            wpath + L"\\DLLs",
            wpath + L"\\lib",
            wpath,
            wpath + L"\\Lib\\site-packages",
#           ifdef ADAPTER_DEVELOPMENT
                getProgramDirectory(),
#           endif
        });
    #else
        std::vector<std::wstring> allPaths({
            wpath + L"/lib/python" PYTHON_VERSION + L".zip",
            wpath + L"/lib/python" PYTHON_VERSION_DOTTED,
            wpath + L"/lib/python" PYTHON_VERSION_DOTTED L"/lib-dynload",
            wpath + L"/lib/python" PYTHON_VERSION_DOTTED L"/site-packages",
#           ifdef ADAPTER_DEVELOPMENT
                Logger::s2w(getProgramDirectory()),
#           endif
        });
    #endif

    return allPaths;
}

std::wstring ensureWideChar(tstring str)
{
    #ifdef _WIN32
        return str;
    #else
        return Logger::s2w(str);
    #endif
}

std::wstring computeProgramNameString(std::wstring wpath)
{
    #ifdef _WIN32
        return wpath + L"\\python.exe";
    #else
        return wpath + L"/bin/python3";
    #endif
}

EmbeddedPython::EmbeddedPython()
{
    LOG_INFO("################################################################################");
    LOG_INFO(std::string("Pythia version: ") + PYTHIA_VERSION);
    LOG_INFO(std::string("Python version: ") + Py_GetVersion());

    auto pythonPath = ensureWideChar(getPythonPath());
    auto programPath = computeProgramNameString(pythonPath);
    auto pathsVector = computePythonPaths(pythonPath);

    // Preconfig
    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);

    preconfig.utf8_mode = 1;

    PyStatus status = Py_PreInitialize(&preconfig);

    if (PyStatus_Exception(status))
    {
        THROW_PYINITIALIZE_EXCEPTION(std::string("Preinitialization exception: ") + status.err_msg)
    }

    // Config
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);

    config.site_import = 1;
    status = PyConfig_SetString(&config, &config.base_exec_prefix, pythonPath.c_str());
    status = PyConfig_SetString(&config, &config.base_executable, programPath.c_str());
    status = PyConfig_SetString(&config, &config.base_prefix, pythonPath.c_str());
    status = PyConfig_SetString(&config, &config.exec_prefix, pythonPath.c_str());
    status = PyConfig_SetString(&config, &config.executable, programPath.c_str());
    status = PyConfig_SetString(&config, &config.prefix, pythonPath.c_str());
    status = PyConfig_SetString(&config, &config.home, pythonPath.c_str());

    for (auto& path : pathsVector)
    {
        status = PyWideStringList_Append(&config.module_search_paths, path.c_str());
    }
    config.module_search_paths_set = 1;

    if (PyStatus_Exception(status))
    {
        THROW_PYINITIALIZE_EXCEPTION(std::string("Initialization exception: ") + status.err_msg)
    }

    // Add custom modules
    PyImport_AppendInittab("pythiainternal", PyInit_pythiainternal);
    PyImport_AppendInittab("pythialogger", PyInit_pythialogger);

    LOG_INFO("Calling Py_InitializeFromConfig()");
    LOG_FLUSH();
    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);

    if (PyStatus_Exception(status))
    {
        THROW_PYINITIALIZE_EXCEPTION(std::string("Py_InitializeFromConfig exception: ") + status.err_msg)
    }

    LOG_INFO(std::string("Python executable from C++: ") + Logger::w2s(Py_GetProgramFullPath()));
    LOG_INFO(std::string("Python home: ") + Logger::w2s(Py_GetPythonHome()));
    LOG_INFO(std::string("Program name: ") + Logger::w2s(Py_GetProgramName()));
    LOG_INFO(std::string("Python paths: ") + Logger::w2s(Py_GetPath()));

    libpythonWorkaround();

    LOG_INFO("Python interpreter initialized. Executing Python code");

    initializeAdapter();
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

void EmbeddedPython::initializeAdapter()
{
    #ifdef ADAPTER_DEVELOPMENT
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

    const std::string text_resource = ResourceLoader::loadTextResource();
    PyObject *compiledString = Py_CompileString(
        text_resource.c_str(),
        "Adapter.py",
        Py_file_input);

    PyObjectGuard pCompiledContents(compiledString);
    if (!pCompiledContents)
    {
        THROW_PYEXCEPTION("Failed to compile embedded python module");
    }

    PyObjectGuard module(PyImport_ExecCodeModule("adapter", pCompiledContents.get()));
    if (!module)
    {
        THROW_PYEXCEPTION("Failed to import python adapter. This is usually caused by BattlEye");
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
        #ifdef _WIN32
        PyObjectGuard pString(PyUnicode_FromWideChar(entry.second.c_str(), -1));
        #else
        PyObjectGuard pString(PyUnicode_FromString(entry.second.c_str()));
        #endif
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

void EmbeddedPython::deinitModules()
{
    /**
    Deinitialize python sources for modules.
    */

    if (!pModule)
    {
        THROW_PYEXCEPTION("Pythia adapter not loaded correctly. Not initializing python modules.")
    }

    // Perform the call adding the mods sources
    PyObjectGuard function(PyObject_GetAttrString(pModule, "deinit_modules"));
    if (!function || !PyCallable_Check(function.get()))
    {
        THROW_PYEXCEPTION("Failed to reference python function 'deinit_modules'");
    }

    PyObjectGuard pResult(PyObject_CallFunctionObjArgs(function.get(), NULL));
    if (pResult)
    {
        return; // Yay!
    }
    else
    {
        THROW_PYEXCEPTION("Failed to execute python deinit_modules function");
    }
}

void EmbeddedPython::deinitializeAdapter()
{
    deinitModules();
    Py_CLEAR(pFunc);
    Py_CLEAR(pModule);
}

void EmbeddedPython::reloadAdapter()
{
    deinitializeAdapter();
    try
    {
        initializeAdapter();
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
    deinitializeAdapter();
    libpythonWorkaroundClose();
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
    snprintf(output, outputSize, "[\"m\",%lu,%lu]", multipartCounter++, (unsigned long)entry.size());
}

// Note: outputSize is the size CONTAINING the null terminator
void returnMultipart(unsigned long multipartID, char *output, int outputSize)
{
    try
    {
        auto &entry = multiparts.at(multipartID);
        auto &retval = entry.front();

        size_t minSize = std::min<size_t>((size_t)outputSize, retval.size() + 1);
        snprintf(output, minSize, "%s", retval.data());

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
