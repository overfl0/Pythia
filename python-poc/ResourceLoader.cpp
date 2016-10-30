#include "stdafx.h"
#include "ResourceLoader.h"
#include <iostream>
#include "Logger.h"

std::string ResourceLoader::loadTextResource(HMODULE moduleHandle, int id, LPTSTR type)
{
    HRSRC resourceHandle = ::FindResource(moduleHandle, MAKEINTRESOURCE(id), type);
    
    if (!resourceHandle)
    {
        std::string msg("Unable to find resource with id: [");
        msg += std::to_string(id);
        msg += "] because of error with code: ";
        msg += std::to_string(::GetLastError());

        LOG_ERROR(msg);
        throw std::runtime_error(msg);
    }

    HGLOBAL resourceData = ::LoadResource(moduleHandle, resourceHandle);
    LPVOID dataFirstByte = ::LockResource(resourceData);

    return std::string(static_cast<const char*>(dataFirstByte));
}
