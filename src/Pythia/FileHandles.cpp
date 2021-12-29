#include "stdafx.h"
// From: http://forum.sysinternals.com/howto-enumerate-handles_topic18892.html

#include <stdio.h>

#include "FileHandles.h"

#include "Logger.h"

#ifdef _WIN32

#ifndef UNICODE
#define UNICODE
#endif

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define SystemHandleInformationEx 64
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2


#define NTAPI __stdcall
typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS(NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_EX
{
    PVOID Object;
    HANDLE ProcessId;
    HANDLE Handle;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_EX, *PSYSTEM_HANDLE_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

PVOID GetLibraryProcAddress(LPCSTR LibraryName, LPCSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

int getOpenFiles(WStringVector &files)
{
    _NtQuerySystemInformation NtQuerySystemInformation =
        (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject =
        (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
    _NtQueryObject NtQueryObject =
        (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo;
    ULONG handleInfoSize = 0x400000;
    HANDLE pid;
    HANDLE processHandle;
    ULONG i;

    files.clear();

    if (!NtQuerySystemInformation ||
        !NtDuplicateObject ||
        !NtQueryObject)
    {
        return 0;
    }

    pid = reinterpret_cast<HANDLE>((uintptr_t)GetCurrentProcessId());
    processHandle = GetCurrentProcess();

    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(handleInfoSize);

    /* NtQuerySystemInformation won't give us the correct buffer size,
    so we guess by doubling the buffer size. */
    while ((status = NtQuerySystemInformation(
        SystemHandleInformationEx,
        handleInfo,
        handleInfoSize,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(handleInfo, handleInfoSize *= 2);

    /* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
    if (!NT_SUCCESS(status))
    {
        //printf("NtQuerySystemInformation failed!\n");
        free(handleInfo);
        return 0;
    }

    for (i = 0; i < handleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE_EX handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;

        /* Check if this handle belongs to the PID the user specified. */
        if (handle.ProcessId != pid)
            continue;

        /* Duplicate the handle so we can query it. */
        if (!NT_SUCCESS(NtDuplicateObject(
            processHandle,
            (HANDLE)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0
        )))
        {
            //printf("[%#x] Error!\n", handle.Handle);
            continue;
        }

        /*
         * We only want files anyway so lets check the type to ensure its a file.
         * As in some cases reading a named pipe would cause a hang. (Thanks TOBII ET5)
         */
        DWORD fileType = GetFileType(dupHandle);
        if (fileType != FILE_TYPE_DISK) {
            CloseHandle(dupHandle);
            continue;
        }

        /* Query the object type. */
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
        )))
        {
            //printf("[%#x] Error!\n", handle.Handle);
            CloseHandle(dupHandle);
            continue;
        }

        /* Query the object name (unless it has an access of
        0x0012019f, on which NtQueryObject could hang. */
        if (handle.GrantedAccess == 0x0012019f)
        {
            /* We have the type, so display that. */
            /*printf(
                "[%#x] %.*S: (did not get name)\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer
            );*/
            free(objectTypeInfo);
            CloseHandle(dupHandle);
            continue;
        }

        objectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength
        )))
        {
            /* Reallocate the buffer and try again. */
            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (!NT_SUCCESS(NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
            )))
            {
                /* We have the type name, so just display that. */
                /*printf(
                    "[%#x] %.*S: (could not get name)\n",
                    handle.Handle,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer
                );*/
                free(objectTypeInfo);
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
        }

        /* Cast our buffer into an UNICODE_STRING. */
        objectName = *(PUNICODE_STRING)objectNameInfo;

        /* Print the information! */
        if (objectName.Length)
        {
            /* The object has a name. */
            /*printf(
                "[%#x] %.*S: %.*S\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer,
                objectName.Length / 2,
                objectName.Buffer
            );*/

            // Only get files
            // Maybe there is a better way of doing this but this should be called
            // only once, anyway.
            if (!wcsncmp(objectTypeInfo->Name.Buffer, L"File", 4))
            {
                //std::wstring fileName(objectName.Buffer, objectName.Length / 2);
                // https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx#maxpath
                // The value below isn't completely correct but bah... (see link above)

                #define MAX_UNICODE_PATH (32767 + 1)
                const DWORD max_unicode_path_size = MAX_UNICODE_PATH * sizeof(wchar_t);
                wchar_t tmpPath[max_unicode_path_size];
                DWORD max_size = (sizeof(tmpPath) / sizeof(wchar_t)) - 1;

                // Naming Files, Paths, and Namespaces
                // https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
                DWORD retval = GetFinalPathNameByHandleW(dupHandle, tmpPath, max_size, FILE_NAME_OPENED);
                if (retval && retval < max_size)
                {
                    files.push_back(tmpPath);
                }
                else
                {
                    //ErrorExit(fileName.c_str());
                }
            }
        }
        else
        {
            /* Print something else. */
            /*printf(
                "[%#x] %.*S: (unnamed)\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer
            );*/
        }

        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);
    }

    free(handleInfo);

    return 1;
}

#else  // ifdef _WIN32

#include <filesystem>

int getOpenFiles(WStringVector& files)
{
    files.clear();

    std::error_code ec;

    auto directory = std::filesystem::directory_iterator("/proc/self/fd", ec);
    if (ec)
    {
        LOG_ERROR("Could not list /proc/self/fd: " + ec.message());
        return 0;
    }

    for (auto& entry : directory)
    {
        if (!std::filesystem::is_symlink(entry, ec))
        {
            if (ec)
            {
                LOG_ERROR(std::string("Could not check symlink ") + entry.path().c_str() + ": " + ec.message());
            }
            continue;
        }

        auto file = std::filesystem::read_symlink(entry, ec);
        if (ec)
        {
            LOG_ERROR(std::string("Could not read symlink ") + entry.path().c_str() + ": " + ec.message());
            continue;
        }

        files.push_back(file);
    }

    return 1;
}

#endif  // ifdef _WIN32
