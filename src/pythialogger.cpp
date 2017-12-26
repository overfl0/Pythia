#include "stdafx.h"
#include "Logger.h"

static PyObject *pythialogger_log(PyObject *self, PyObject *args)
{
    // TODO: Reference counting!
    const char *format;

    if (!PyArg_ParseTuple(args, "s", &format))  // Sets exception on error
        return nullptr;  // Can return NULL here

    LOG_INFO(format);
    Py_RETURN_NONE;  // No exception, Should return object(None)
}

static PyObject *pythialogger_critical(PyObject *self, PyObject *args)
{
    return pythialogger_log(self, args);
}

static PyObject *pythialogger_info(PyObject *self, PyObject *args)
{
    return pythialogger_log(self, args);
}

static PyObject *pythialogger_debug(PyObject *self, PyObject *args)
{
    return pythialogger_log(self, args);
}

static PyObject *pythialogger_error(PyObject *self, PyObject *args)
{
    return pythialogger_log(self, args);
}

static PyObject *pythialogger_exception(PyObject *self, PyObject *args)
{
    // TODO: Fetch the exception!!!
    return pythialogger_log(self, args);
}

static PyMethodDef PythialoggerMethods[] =
{

    { "log",  pythialogger_log, METH_VARARGS, "Run the logger." },
    { "critical",  pythialogger_critical, METH_VARARGS, "Run the logger." },
    { "info",  pythialogger_info, METH_VARARGS, "Run the logger." },
    { "debug",  pythialogger_debug, METH_VARARGS, "Run the logger." },
    { "error",  pythialogger_error, METH_VARARGS, "Run the logger." },
    { "exception",  pythialogger_exception, METH_VARARGS, "Run the logger." },
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
