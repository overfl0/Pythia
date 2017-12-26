#include "stdafx.h"
#include "../common.h"

static PyObject *pythiainternal_version(PyObject *self, PyObject *args)
{
    return PyUnicode_FromString(PYTHIA_VERSION);
}

static PyMethodDef PythialoggerMethods[] =
{

    { "version",  pythiainternal_version, METH_NOARGS, "Get Pythia version." },
    { NULL, NULL, 0, NULL }        /* Sentinel */
};

static struct PyModuleDef pythiainternalmodule =
{
    PyModuleDef_HEAD_INIT,
    "pythiainternal",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
              or -1 if the module keeps state in global variables. */
    PythialoggerMethods
};

PyMODINIT_FUNC PyInit_pythiainternal(void)
{
    return PyModule_Create(&pythiainternalmodule);
}
