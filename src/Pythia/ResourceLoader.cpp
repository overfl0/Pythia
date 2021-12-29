#include "stdafx.h"
#include "ResourceLoader.h"
#include "Logger.h"
#include "python_generated/py_adapter.h"

std::string ResourceLoader::loadTextResource()
{
    // TODO: Parametrize this later to add different resources to load
    return std::string(reinterpret_cast<const char*>(PY_ADAPTER), sizeof(PY_ADAPTER));
}
