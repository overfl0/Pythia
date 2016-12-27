#include "stdafx.h"
#include "Logger.h"
#include <sstream> // stringstream
#include <shlobj.h>    // for SHGetFolderPath
#include <string>

std::string Logger::makeFilename()
{
    CHAR buffer[MAX_PATH];
    
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buffer)))
    {
        // Append product-specific path
        return std::string(buffer) + "\\Arma 3\\python.log";
    }

    return ""; 
}
