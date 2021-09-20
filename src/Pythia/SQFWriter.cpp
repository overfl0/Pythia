#include "stdafx.h"
#include <Python.h>
#include "SQFWriter.h"

#include <stdlib.h>
#include <string>
#include <sstream>

#include "ExceptionFetcher.h"
#include "third_party/double-conversion/double-conversion.h"

#ifndef _CVTBUFSIZE
// _CVTBUFSIZE is the maximum size for the per-thread conversion buffer.  It
// should be at least as long as the number of digits in the largest double
// precision value (?.?e308 in IEEE arithmetic).  We will use the same size
// buffer as is used in the printf support routines.
//
// (This value actually allows 40 additional decimal places; even though there
// are only 16 digits of accuracy in a double precision IEEE number, the user may
// ask for more to effect zero padding.)
#define _CVTBUFSIZE (309 + 40) // # of digits in max. dp value + slop
#endif

namespace SQFWriter
{
    void encode(PyObject *obj, MultipartResponseWriter *writer)
    {
        if (obj == nullptr)
        {
            writer->writeBytes("Null pointer! File a bug report please!!!");
            return;
        }

        //= None ===============================================================
        //Py_BuildValue("");
        if (obj == Py_None)
        {
            writer->writeBytes("nil");
            return;
        }

        //= Boolean values =====================================================
        //PyObject* PyBool_FromLong(long v)
        if (obj == Py_True)
        {
            writer->writeBytes("True");
            return;
        }

        if (obj == Py_False)
        {
            writer->writeBytes("False");
            return;
        }

        //= Integers ===========================================================
        //if (obj->ob_type == &PyLong_Type)
        if (PyLong_Check(obj))
        {
            long long value;
            int overflow;

            value = PyLong_AsLongLongAndOverflow(obj, &overflow);
            if (!overflow)
            {
                writer->writeBytes(std::to_string(value).c_str());
                return;
            }

            writer->writeBytes("OVERFLOW!");
            return;
        }

        //= Floats =============================================================
        //if (obj->ob_type == &PyFloat_Type)
        if (PyFloat_Check(obj))
        {
            double value = PyFloat_AsDouble(obj);

            if (PyErr_Occurred())
            {
                PyErr_Clear();
                writer->writeBytes("OVERFLOW!");
                return;
            }

            char sValue[_CVTBUFSIZE];
            double_conversion::StringBuilder sb(sValue, 26);
            double_conversion::DoubleToStringConverter::EcmaScriptConverter().ToShortest(value, &sb);
            sb.Finalize();
            writer->writeBytes(sValue);
            return;
        }

        //= Unicode ============================================================
        if (PyUnicode_Check(obj))
        {
            const char *obj_utf8 = PyUnicode_AsUTF8(obj);
            if (obj_utf8 == nullptr)
            {
                if (PyErr_Occurred())
                {
                    PyErr_Clear();
                }
                writer->writeBytes("Error while converting the string to utf8. Report a bug!");
                return;
            }

            // Compute the output size first
            int required_size = 2; // ""
            for (const char *p = obj_utf8; *p; ++p)
            {
                ++required_size;
                if (*p == '"')
                {
                    ++required_size;
                }
            }

            std::string retval;
            retval.resize(required_size);
            retval[0] = retval[required_size - 1] = '"';

            // Fill the array
            int i = 1;
            for (const char *p = obj_utf8; *p; ++p)
            {
                if (*p == '"')
                {
                    retval[i++] = '"';
                }
                retval[i++] = *p;
            }

            writer->writeBytes(retval.c_str());
            return;
        }

        //= Iterable objects ===================================================
        PyObject *iterator = PyObject_GetIter(obj);
        if (iterator)
        {
            writer->writeBytes("[");
            bool first = true;
            PyObject *item = nullptr;

            while (item = PyIter_Next(iterator))
            {
                /* do something with item */
                if (first)
                {
                    first = false;
                }
                else
                {
                    writer->writeBytes(",");
                }

                encode(item, writer);
                /* release reference when done */
                Py_DECREF(item);
            }

            if (PyErr_Occurred()) {
                writer->writeBytes("Error while iterating iterator. Report a bug!!!");
                return;
            }

            writer->writeBytes("]");
            Py_DECREF(iterator);
            return;
        }
        else
        {
            // Clear the TypeError exception that occurred because obj is not iterable
            PyErr_Clear();
        }

        //= Type unknown. Kept here for testing ================================

        if (PyErr_Occurred()) {
            /* propagate error */
            writer->writeBytes(PyExceptionFetcher().getError().c_str());
            return;
        }

        writer->writeBytes("Unknown variable type that is not supported! Submit a pull request!");
        return;

        // Note: this code is never executed and is kept for debugging purposes.
        PyObject *repr_obj = PyObject_Repr(obj);
        if (repr_obj)
        {
            const char *value_utf8 = PyUnicode_AsUTF8(repr_obj);
            if (value_utf8)
            {
                writer->writeBytes((std::string("Str() gave: ") + value_utf8).c_str());
                return;
            }
            else {
                writer->writeBytes("Could not convert to unicode");
                return;
            }
        }
        else {
            writer->writeBytes("Could not call repr()");
            return;
        }

        writer->writeBytes("");
        return;
    }
}
