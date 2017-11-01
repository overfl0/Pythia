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
    if (name.length() < 1)
    {
        return false;
    }

    for (char &c : name)
    {
        if (!isalnum(c) && c != '_')
        {
            return false;
        }
    }
    return true;
}

static std::string getPythiaModuleName(std::ifstream &stream)
{
    std::string pythiaModuleName;
    stream >> pythiaModuleName;
    return pythiaModuleName;
}


/**
   Get loaded python mods.
   Scan all the open file handles for .pbo files.
   Then go one directory above those files and check if there is a $PYTHIA$
   file. If so, load it and read the python module name from the pythia dir.

   Return the list of module names along with paths to those modules.
   (string -> wstring)
 */
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
