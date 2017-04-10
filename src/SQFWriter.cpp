#include "stdafx.h"
#include "Python.h"
#include "SQFWriter.h"

#include <string>
#include <sstream>

#include "../src/ExceptionFetcher.h"

// TODO: Improve iterables performance

namespace SQFWriter
{
    std::string encode(PyObject *obj)
    {
        if (obj == nullptr)
        {
            return "Null pointer! File a bug report please!!!";
        }

        //= None ===============================================================
        //Py_BuildValue("");
        if (obj == Py_None)
        {
            return "nil";
        }

        //= Boolean values =====================================================
        //PyObject* PyBool_FromLong(long v)
        if (obj == Py_True)
        {
            return "True";
        }
        
        if (obj == Py_False)
        {
            return "False";
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
                return std::to_string(value);
            }

            return "OVERFLOW!";
        }

        //= Floats =============================================================
        //if (obj->ob_type == &PyFloat_Type)
        if (PyFloat_Check(obj))
        {
            double value = PyFloat_AsDouble(obj);

            if (PyErr_Occurred())
            {
                PyErr_Clear();
                return "OVERFLOW!";
            }

            std::stringstream strstream;
            strstream << value;
            return strstream.str();
        }

        //= Unicode ============================================================
        if (PyUnicode_Check(obj))
        {
            char *obj_utf8 = PyUnicode_AsUTF8(obj);
            if (obj_utf8 == nullptr)
            {
                if (PyErr_Occurred())
                {
                    PyErr_Clear();
                }
                return "Error while converting the string to utf8. Report a bug!";
            }

            // Compute the output size first
            int required_size = 2; // ""
            for (char *p = obj_utf8; *p; ++p)
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
            for (char *p = obj_utf8; *p; ++p)
            {
                if (*p == '"')
                {
                    retval[i++] = '"';
                }
                retval[i++] = *p;
            }

            return retval;
        }

        //= Iterable objects ===================================================
        PyObject *iterator = PyObject_GetIter(obj);
        if (iterator)
        {
            std::string retval = "[";
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
                    retval += ',';
                }

                retval += encode(item);
                /* release reference when done */
                Py_DECREF(item);
            }

            if (PyErr_Occurred()) {
                return "Error while iterating iterator. Report a bug!!!";
            }

            retval += "]";

            Py_DECREF(iterator);

            return retval;
        }
        else
        {
            // Clear the TypeError exception that occurred because obj is not iterable
            PyErr_Clear();
        }

        //= Type unknown. Kept here for testing ================================

        if (PyErr_Occurred()) {
            /* propagate error */
            return PyExceptionFetcher().getError();
        }

        return "Unknown variable type that is not supported! Submit a pull request!";

        // Note: this code is never executed and is kept for debugging purposes.
        PyObject *repr_obj = PyObject_Repr(obj);
        if (repr_obj)
        {
            char *value_utf8 = PyUnicode_AsUTF8(repr_obj);
            if (value_utf8)
            {
                return std::string("Str() gave: ") + value_utf8;
            }
            else {
                return "Could not convert to unicode";
            }
        }
        else {
            return "Could not call repr()";
        }

        return "";
    }
}
