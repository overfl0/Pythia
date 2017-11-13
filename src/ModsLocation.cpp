#include "stdafx.h"
#include "ModsLocation.h"
#include "FileHandles.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>

namespace fs = std::experimental::filesystem;

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
   Check if the given directory contains python code usable by Pythia.
 */
static void tryAddingPythiaModule(modules_t &modules, const std::wstring path)
{
    auto pythiaFile = path + L"\\$PYTHIA$";

    std::ifstream pythiaFileHandle;
    pythiaFileHandle.open(pythiaFile, std::ios::binary);
    if (!pythiaFileHandle.good())
    {
        // File probably doesn't exist
        return;
    }

    std::string pythiaModuleName = getPythiaModuleName(pythiaFileHandle);
    if (!validPythiaModuleName(pythiaModuleName))
    {
        return;
    }

    // Add the current directory to the mods list
    modules[pythiaModuleName] = path;
}

/**
   Get loaded python mods.
   Scan all the open file handles for .pbo files and open the parent directory.
   Those are hopefully mod dirs. Then, iterate all the directories inside.
   Check if there is a $PYTHIA$ file in each of those directories.
   If so, load it and read the python module name from that directory.

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
        std::error_code ec;

        for (auto& entry : fs::directory_iterator(parent, ec))
        {
            if (fs::is_directory(entry))
            {
                tryAddingPythiaModule(modules, entry.path());
            }
        }
    }

    return modules;
}
