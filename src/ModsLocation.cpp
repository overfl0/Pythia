#include "stdafx.h"
#include "FileHandles.h"

#include <filesystem>

using namespace std::tr2::sys;

inline bool ends_with(std::wstring const & value, std::wstring const & ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

void getDirectories(std::wstring const & fileEndingFilter=L"")
{
    WStringVector files;
    std::unordered_set<std::wstring> directories;
    int retval = getOpenFiles(files);

    for (auto &file : files)
    {
        path filePath(file);
        /*if (ends_with(file, fileEndingFilter))
        {
            directories.insert(file);
        }*/
        std::wstring parent = filePath.parent_path();
        std::wstring extension = filePath.extension();
        int a = 5;
    }



}
