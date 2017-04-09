#include "stdafx.h"
#include "Python.h"
#include "SQFWriter.h"

#include <string>
#include <sstream>

#include "../src/ExceptionFetcher.h"

// TODO: Improve iterables performance
// TODO: Add null checks, just to be sure

namespace SQFWriter
{
    std::string encode(PyObject *obj)
    {
        if (obj == nullptr)
        {
            // TODO: Probably return an exception
            return "Null pointer! WTFBBQ!";
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
            // TODO: Check for exceptions
        }

        //= Floats =============================================================
        //if (obj->ob_type == &PyFloat_Type)
        if (PyFloat_Check(obj))
        {
            double value = PyFloat_AsDouble(obj);
            std::stringstream strstream;
            strstream << value;
            return strstream.str();

            //return "OVERFLOW!";
            // TODO: Check for exceptions
            //PyErr_Occurred() 
        }

        //= Unicode ============================================================
        if (PyUnicode_Check(obj))
        {
            char *obj_utf8 = PyUnicode_AsUTF8(obj);

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
