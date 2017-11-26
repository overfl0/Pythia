#include "stdafx.h"
#include "Python.h"
#include "SQFReader.h"

//#include "../src/ExceptionFetcher.h"

using namespace std;

namespace SQFReader
{
    // Returns a new PyObject reference or NULL on error
    inline PyObject *try_parse_number(const char **start)
    {
        const char *end = *start;
        char isFloat = false;

        if (*end == '-')
        {
            end++;
        }
        // TODO: Check if '-' is present only once

        while ((*end >= '0' && *end <= '9') || *end == '.')
        {
            if (*end == '.')
            {
                if (isFloat)
                {
                    // '.' is present twice!
                    // TODO: Raise exception
                }
                isFloat = true;
            }
            end++;
        }

        std::string tmp_value(*start, end - *start);
        // TODO: reference counting
        PyObject *number;
        if (!isFloat)
        {
            number = PyLong_FromString(tmp_value.c_str(), nullptr, 10);
        }
        else
        {
            double cDouble = atof(tmp_value.c_str());
            number = PyFloat_FromDouble(cDouble);
        }

        *start = end;
        return number;
    }

    // Returns a new PyObject reference or NULL on error
    inline PyObject *try_parse_string_noescape(const char **start)
    {
        (*start)++;
        const char *end = *start;

        while (*end != '\'')
            end++;

        // TODO: reference counting
        PyObject *retval = PyUnicode_FromStringAndSize(*start, end - *start);
        *start = end + 1;
        return retval;
    }

    // Returns a new PyObject reference or NULL on error
    inline PyObject *try_parse_string_escape(const char **start)
    {
        (*start)++;
        int escapedCount = 0;
        const char *end = *start;

        // Compute the length of the real string
        for (;;end++)
        {
            if (*end == '\0')
            {
                // TODO: END OF C-STRING! Raise exception!!!
                return nullptr;
            }

            if (*end == '"')
            {
                if (end[1] != '"')
                {
                    // End of SQF string
                    break;
                }
                escapedCount++;
                end++;
            }
        }

        int realStringLength = end - *start - escapedCount;
        char *realString = new char[realStringLength + 1];
        char* rp = realString;

        // Unescape the string
        for (const char *p = *start;; p++, rp++)
        {
            if (*p == '"')
            {
                if (p[1] != '"')
                {
                    break;
                }
                p++;
            }
            *rp = *p;
        }
        realString[realStringLength] = '\0';

        int len = rp - realString;
        PyObject *retval = PyUnicode_FromStringAndSize(realString, rp - realString);
        *start = end + 1;

        delete [] realString;
        return retval;
    }

    // Returns a new PyObject reference or NULL on error
    inline PyObject *try_parse_true(const char **start)
    {
        if (((*start)[1] == 'R' || (*start)[1] == 'r') &&
            ((*start)[2] == 'U' || (*start)[2] == 'u') &&
            ((*start)[3] == 'E' || (*start)[3] == 'e'))
        {
            *start += 4;
            Py_RETURN_TRUE;
        }
        return nullptr;
    }

    // Returns a new PyObject reference or NULL on error
    inline PyObject *try_parse_false(const char **start)
    {
        if (((*start)[1] == 'A' || (*start)[1] == 'a') &&
            ((*start)[2] == 'L' || (*start)[2] == 'l') &&
            ((*start)[3] == 'S' || (*start)[3] == 's') &&
            ((*start)[4] == 'E' || (*start)[4] == 'e'))
        {
            *start += 5;
            Py_RETURN_FALSE;
        }
        return nullptr;
    }

    // Returns a new PyObject reference or NULL on error
    inline PyObject *try_parse_array(const char **start)
    {
        (*start)++;

        PyObject* list = PyList_New(0);
        if (list == nullptr)
        {
            // TODO: Log the error
            return nullptr;
        }

        while(true)
        {
            if (**start == ']')
            {
                (*start)++;
                return list;
            }

            PyObject *obj = decode(start);
            if (obj == nullptr)
            {
                // TODO: Return some message
                Py_DECREF(list); // garbage-collect the list and its contents
                return nullptr;
            }

            // TODO: Return value check
            int retval = PyList_Append(list, obj); // Increases obj's refcount
            Py_DECREF(obj);
            if (retval != 0)
            {
                // TODO: Return some message
                // The docs say that this raises an exception
                // Not sure how to act here
                Py_DECREF(list); // garbage-collect the list and its contents
                return nullptr;
            }

            while (**start == ' ')
                (*start)++;

            if (**start == ',')
            {
                (*start)++;
            }
            else if (**start != ']')
            {
                // TODO: Return some message
                Py_DECREF(list); // garbage-collect the list and its contents
                return nullptr;
            }
        }
    }

    // Returns a new PyObject reference or NULL on error
    // IMPORTANT: The object MUST be Py_DECREF'ed after use to prevent leakage
    PyObject *decode(const char **start)
    {
        // Drop whitespaces
        while (**start == ' ')
            (*start)++;

        if ((**start >= '0' && **start <= '9') || **start == '-')
        {
            return try_parse_number(start);
        }
        else if (**start == '[')
        {
            return try_parse_array(start);
        }
        else if (**start == '"')
        {
            return try_parse_string_escape(start);
        }
        else if (**start == '\'')
        {
            return try_parse_string_noescape(start);
        }
        else if (**start == 'T' || **start == 't')
        {
            return try_parse_true(start);
        }
        else if (**start == 'F' || **start == 'f')
        {
            return try_parse_false(start);
        }

        // TODO: check that the buffer is empty

        return nullptr;
    }
}
