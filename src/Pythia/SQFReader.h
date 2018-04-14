#pragma once

#include "stdafx.h"

namespace SQFReader
{
    class ParseException : public std::runtime_error
    {
    public:
        const char *where_error;

        ParseException(const std::string& what_arg, const char *where_arg) : std::runtime_error(what_arg)
        {
            where_error = where_arg;
        }
    };

    PyObject *decode(const char *sqf);
}
