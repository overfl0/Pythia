#include "stdafx.h"
#include "ModsLocation.h"
#include "FileHandles.h"
#include "Paths.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>

#include "Logger.h"

typedef std::unordered_set<tstring> dlist;

bool hasEnding(tstring const &fullString, tstring const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    }
    else {
        return false;
    }
}

dlist getDirectories(tstring const & fileExtension=LITERAL(""))
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
static void tryAddingPythiaModule(modules_t &modules, const tstring path)
{
    auto pythiaFile = std::filesystem::path(path) / LITERAL("$PYTHIA$");

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

    dlist directoriesList = getDirectories(LITERAL(".pbo"));
    for (auto &directory : directoriesList)
    {
        std::filesystem::path parent = getPathDirectory(directory);
        std::error_code ec;

        auto directory_iter = std::filesystem::directory_iterator(parent, ec);
        if (ec)
        {
            LOG_ERROR(std::string("Could not list ") + parent.u8string() + ": " + ec.message());
            continue;
        }

        for (auto& entry : directory_iter)
        {
            if (std::filesystem::is_directory(entry, ec))
            {
                tryAddingPythiaModule(modules, entry.path());
            }
            else
            {
                if (ec)
                {
                    LOG_ERROR(std::string("Could not check if directory: ") + entry.path().u8string() + ": " + ec.message());
                    continue;
                }
            }
        }
    }

    return modules;
}
