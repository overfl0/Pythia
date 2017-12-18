#pragma once

#include "stdafx.h"
#include "ResponseWriter.h"

namespace SQFWriter
{
    void encode(PyObject *obj, MultipartResponseWriter *writer);
}
