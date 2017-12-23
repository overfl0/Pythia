#include "stdafx.h"
#include "Logger.h"
#include <sstream> // stringstream
#include <shlobj.h>    // for SHGetFolderPath
#include <string>

#ifndef LOGGER_FILENAME
#define LOGGER_FILENAME "cpythia.log"
#endif

std::string Logger::makeFilename()
{
    CHAR buffer[MAX_PATH];
    
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buffer)))
    {
        // Append product-specific path
        // TODO: Implement a better way of initializing the logger
        return std::string(buffer) + "\\Arma 3\\" + LOGGER_FILENAME;
    }

    return LOGGER_FILENAME;
}
