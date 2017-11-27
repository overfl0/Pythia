#include "stdafx.h"
#include "Python.h"
#include "SQFReader.h"

using namespace std;

#define THROW_PARSEERROR(_msg_) \
{\
    throw ParseException(_msg_ + std::string(" near: ") + std::string(*start), *start);\
}

namespace SQFReader
{
    /*
    Note on reference counting in this parser:
    Because you can have arrays containing other python objects (which may
    themselves also be arrays, etc...), and the resulting object will be
    directly passed to Python code, these functions are operating on Python
    objects that have to have the reference counting handled manually instead
    of wrapping them into refcounting classes.
    */
    PyObject *decode_part(const char **start);

    // Returns a new PyObject reference
    inline PyObject *try_parse_number(const char **start)
    {
        const char *end = *start;
        char isFloat = false;

        if (*end == '-')
        {
            end++;
            if (*end == '-')
            {
                // Uhhh... "--5"?
                THROW_PARSEERROR("Error when parsing number");
            }
        }

        while ((*end >= '0' && *end <= '9') || *end == '.')
        {
            if (*end == '.')
            {
                if (isFloat)
                {
                    // '.' is present twice!
                    THROW_PARSEERROR("Error when parsing number");
                }
                isFloat = true;
            }
            end++;
        }

        std::string tmp_value(*start, end - *start);
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

        if (number == nullptr)
        {
            THROW_PARSEERROR("Error when parsing number");
        }

        *start = end;
        return number;
    }

    // Returns a new PyObject reference
    inline PyObject *try_parse_string_noescape(const char **start)
    {
        (*start)++;
        const char *end = *start;

        while (*end != '\'')
            end++;

        PyObject *retval = PyUnicode_FromStringAndSize(*start, end - *start);
        if (retval == nullptr)
        {
            THROW_PARSEERROR("Error when parsing single-quoted string");
        }

        *start = end + 1;
        return retval;
    }

    // Returns a new PyObject reference
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
                THROW_PARSEERROR("Error when parsing double-quoted string: premature end");
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
        delete[] realString;

        if (retval == nullptr)
        {
            THROW_PARSEERROR("Error when parsing double-quoted string");
        }

        *start = end + 1;
        return retval;
    }

    // Returns a new PyObject reference
    inline PyObject *try_parse_true(const char **start)
    {
        if (((*start)[1] == 'R' || (*start)[1] == 'r') &&
            ((*start)[2] == 'U' || (*start)[2] == 'u') &&
            ((*start)[3] == 'E' || (*start)[3] == 'e'))
        {
            *start += 4;
            Py_RETURN_TRUE;
        }

        THROW_PARSEERROR("Error when parsing boolean");
    }

    // Returns a new PyObject reference
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

        THROW_PARSEERROR("Error when parsing boolean");
    }

    // Returns a new PyObject reference
    inline PyObject *try_parse_array(const char **start)
    {
        (*start)++;

        PyObject* list = PyList_New(0);
        if (list == nullptr)
        {
            THROW_PARSEERROR("Internal error when creating a list");
        }

        while(true)
        {
            if (**start == ']')
            {
                (*start)++;
                return list;
            }

            PyObject *obj;
            try
            {
                obj = decode_part(start);
            }
            catch (...)
            {
                Py_DECREF(list); // garbage-collect the list and its contents
                throw;
            }

            int retval = PyList_Append(list, obj); // Increases obj's refcount
            Py_DECREF(obj);
            if (retval != 0)
            {
                // The docs say that this raises a Python exception
                // Not sure how to act here
                Py_DECREF(list); // garbage-collect the list and its contents
                THROW_PARSEERROR("Internal error when appending to list");
            }

            while (**start == ' ')
                (*start)++;

            if (**start == ',')
            {
                (*start)++;
            }
            else if (**start != ']')
            {
                Py_DECREF(list); // garbage-collect the list and its contents
                THROW_PARSEERROR("Expected end of array");
            }
        }
    }

    // Returns a new PyObject reference
    PyObject *decode_part(const char **start)
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

        THROW_PARSEERROR("Unexpected character");
    }

    // Returns a new PyObject reference
    // IMPORTANT: The object MUST be Py_DECREF'ed after use to prevent leakage
    // Throws std::runtime_error on parse error with an explanation
    PyObject *decode(const char *sqf)
    {
        const char **start = &sqf;
        try
        {
            PyObject *obj = decode_part(start);

            // Check that the buffer is empty
            while (**start == ' ')
                (*start)++;

            if (**start != '\0')
            {
                Py_DECREF(obj);
                THROW_PARSEERROR("Unexpected character");
            }
            return obj;
        }
        catch (ParseException ex)
        {
            throw; // Rethrow. Prevents from being caught by (...) below
        }
        catch (...)
        {
            THROW_PARSEERROR("Unknown parse error");
        }
    }
}
