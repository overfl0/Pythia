#include "stdafx.h"
#include "ModsLocation.h"
#include "FileHandles.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>

typedef std::unordered_set<std::wstring> dlist;

std::wstring getPathDirectory(std::wstring path)
{
    // Returns the whole string if no backslash is present
    return path.substr(0, path.find_last_of(L"/\\"));
}

bool hasEnding(std::wstring const &fullString, std::wstring const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    }
    else {
        return false;
    }
}

dlist getDirectories(std::wstring const & fileExtension=L"")
{
    WStringVector files;
    dlist directories;
    int retval = getOpenFiles(files);
    if (!retval)
        return directories;

    for (auto &file : files)
    {
        if (hasEnding(file, fileExtension))
        {
            directories.insert(getPathDirectory(file));
        }
    }

    return directories;
}

static bool validPythiaModuleName(std::string name)
{
    for (char &c : name)
    {
        if (!isalnum(c))
        {
            return false;
        }
    }
    return true;
}

static std::string getPythiaModuleName(std::ifstream &stream)
{
    std::stringstream strStream;
    strStream << stream.rdbuf();
    std::string pythiaModuleName = strStream.str();
    return pythiaModuleName;
}

// TODO: Clean all this code up!

modules_t getPythiaModulesSources()
{
    modules_t modules;

    dlist directoriesList = getDirectories(L".pbo");
    for (auto &directory : directoriesList)
    {
        auto parent = getPathDirectory(directory);
        auto pythiaFile = parent + L"\\$PYTHIA$";

        std::ifstream pythiaFileHandle;
        pythiaFileHandle.open(pythiaFile, std::ios::binary);
        if (!pythiaFileHandle.good())
        {
            // File probably doesn't exist
            continue;
        }

        std::string pythiaModuleName = getPythiaModuleName(pythiaFileHandle);
        if (!validPythiaModuleName(pythiaModuleName))
        {
            continue;
        }

        auto codeDirectory = parent + L"\\pythia";
        if (std::experimental::filesystem::is_directory(codeDirectory)) {
            if (std::experimental::filesystem::exists(codeDirectory)) {
                modules[pythiaModuleName] = codeDirectory;
            }
        }
    }

    return modules;
}
