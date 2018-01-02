#include "stdafx.h"
#include "../Logger.h"

static PyObject *pythialogger_debug(PyObject *self, PyObject *args)
{
    const char *format;

    if (!PyArg_ParseTuple(args, "s", &format))  // Sets exception on error
        return nullptr;  // Can return NULL here

    LOG_DEBUG("{}", format);
    Py_RETURN_NONE;  // No exception, Should return object(None)
}

static PyObject *pythialogger_info(PyObject *self, PyObject *args)
{
    const char *format;

    if (!PyArg_ParseTuple(args, "s", &format))  // Sets exception on error
        return nullptr;  // Can return NULL here

    LOG_INFO("{}", format);
    Py_RETURN_NONE;  // No exception, Should return object(None)
}

static PyObject *pythialogger_warn(PyObject *self, PyObject *args)
{
    const char *format;

    if (!PyArg_ParseTuple(args, "s", &format))  // Sets exception on error
        return nullptr;  // Can return NULL here

    LOG_WARN("{}", format);
    Py_RETURN_NONE;  // No exception, Should return object(None)
}

static PyObject *pythialogger_error(PyObject *self, PyObject *args)
{
    const char *format;

    if (!PyArg_ParseTuple(args, "s", &format))  // Sets exception on error
        return nullptr;  // Can return NULL here

    LOG_ERROR("{}", format);
    Py_RETURN_NONE;  // No exception, Should return object(None)
}

static PyObject *pythialogger_critical(PyObject *self, PyObject *args)
{
    const char *format;

    if (!PyArg_ParseTuple(args, "s", &format))  // Sets exception on error
        return nullptr;  // Can return NULL here

    LOG_CRITICAL("{}", format);
    Py_RETURN_NONE;  // No exception, Should return object(None)
}

static PyObject *pythialogger_exception(PyObject *self, PyObject *args)
{
    // TODO: Fetch the exception!!!
    const char *format;

    if (!PyArg_ParseTuple(args, "s", &format))  // Sets exception on error
        return nullptr;  // Can return NULL here

    LOG_ERROR("{}", format);
    Py_RETURN_NONE;  // No exception, Should return object(None)
}

static PyMethodDef PythialoggerMethods[] =
{
    { "debug",  pythialogger_debug, METH_VARARGS, "Run the logger with the debug level." },
    { "info",  pythialogger_info, METH_VARARGS, "Run the logger with the info level." },
    { "warn",  pythialogger_warn, METH_VARARGS, "Run the logger with the warn level." },
    { "error",  pythialogger_error, METH_VARARGS, "Run the logger with the error level." },
    { "critical",  pythialogger_critical, METH_VARARGS, "Run the logger with the critical level." },
    { "exception",  pythialogger_exception, METH_VARARGS, "Run the logger with the exception level." },
    { NULL, NULL, 0, NULL }        /* Sentinel */
};

static struct PyModuleDef pythialoggermodule =
{
    PyModuleDef_HEAD_INIT,
    "spdlog",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
              or -1 if the module keeps state in global variables. */
    PythialoggerMethods
};

PyMODINIT_FUNC
PyInit_pythialogger(void)
{
    return PyModule_Create(&pythialoggermodule);
}
