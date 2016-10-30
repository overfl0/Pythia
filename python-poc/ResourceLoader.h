#pragma once

#include <string>

namespace ResourceLoader
{
    std::string loadTextResource(HMODULE moduleHandle, int id, LPTSTR type);
};

