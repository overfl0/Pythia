#include "stdafx.h"
#include "Python.h"
#include "SQFReader.h"

#include <string>
#include <sstream>

#include "../src/ExceptionFetcher.h"

#include <cstdio>
#include <string>
#include <vector>
#include <utility>
#include <iterator>
#include <array>
#include <algorithm>
#include <chrono>

using namespace std;

namespace SQFReader
{
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

        // TODO: reference counting
        PyObject *number;
        if (!isFloat)
        {
            number = PyLong_FromString(*start, nullptr, 10);
        }
        else
        {
            double cDouble = atof(*start);
            number = PyFloat_FromDouble(cDouble);
        }

        *start = end;
        return number;
    }

    inline PyObject *try_parse_string_noescape(const char **start)
    {
        (*start)++;
        const char *end = *start;

        while (*end != '\'')
            end++;

        // TODO: Check the size value with regard to utf-8
        // TODO: reference counting
        PyObject *retval = PyUnicode_FromStringAndSize(*start, end - *start);
        *start = end + 1;
        return retval;
    }

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

        // TODO: Check the size value with regard to utf-8
        // TODO: reference counting
        int len = rp - realString;
        PyObject *retval = PyUnicode_FromStringAndSize(realString, rp - realString);
        *start = end + 1;

        delete [] realString;
        return retval;
    }

    inline PyObject *try_parse_true(const char **start)
    {
        if (((*start)[1] == 'R' || (*start)[1] == 'r') &&
            ((*start)[2] == 'U' || (*start)[2] == 'u') &&
            ((*start)[3] == 'E' || (*start)[3] == 'e'))
        {
            *start += 4;
            // TODO: Handle reference counting
            Py_RETURN_TRUE;
        }
        return nullptr;
    }

    inline PyObject *try_parse_false(const char **start)
    {
        if (((*start)[1] == 'A' || (*start)[1] == 'a') &&
            ((*start)[2] == 'L' || (*start)[2] == 'l') &&
            ((*start)[3] == 'S' || (*start)[3] == 's') &&
            ((*start)[4] == 'E' || (*start)[4] == 'e'))
        {
            *start += 5;
            // TODO: Handle reference counting
            Py_RETURN_FALSE;
        }
        return nullptr;
    }

    PyObject *decode(const char *start)
    {
        // Drop whitespaces
        while (*start == ' ')
            start++;

        // If number
        if ((*start >= '0' && *start <= '9') || *start == '-')
        {
            return try_parse_number(&start);
        }
        else if (*start == '[')
        {
            // parse array
        }
        else if (*start == '"')
        {
            return try_parse_string_escape(&start);
        }
        else if (*start == '\'')
        {
            return try_parse_string_noescape(&start);
        }
        else if (*start == 'T' || *start == 't')
        {
            return try_parse_true(&start);
        }
        else if (*start == 'F' || *start == 'f')
        {
            return try_parse_false(&start);
        }

        // TODO: check that the buffer is empty

        return nullptr;
    }
}
