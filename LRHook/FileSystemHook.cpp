#include <Windows.h>
#include <detours.h>
#include "LRHookFunc.h"
#include "KernelbaseHook.h"
#include "FileSystemHook.h"

namespace
{
    // Use the emulated code page for app-supplied narrow paths. Keep all actual
    // filesystem operations Unicode, including names returned by enumeration.
    class EmulatedPath
    {
        LPWSTR value;
    public:
        explicit EmulatedPath(LPCSTR path) : value(nullptr)
        {
            if (!path) { SetLastError(ERROR_INVALID_PARAMETER); return; }
            value = MultiByteToWideCharInternal(path, settings.CodePage);
            if (!value) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        ~EmulatedPath()
        {
            DWORD error = GetLastError();
            if (value) FreeStringInternal(value);
            SetLastError(error);
        }
        EmulatedPath(const EmulatedPath&) = delete;
        EmulatedPath& operator=(const EmulatedPath&) = delete;
        LPCWSTR Get() const { return value; }
    };

    auto OriginalGetFileAttributesA = ResolveKernelBaseFunction("GetFileAttributesA", GetFileAttributesA);
    auto Kernel32GetFileAttributesA = ResolveAdditionalKernel32Function("GetFileAttributesA", OriginalGetFileAttributesA);
    auto OriginalFindFirstFileA = ResolveKernelBaseFunction("FindFirstFileA", FindFirstFileA);
    auto Kernel32FindFirstFileA = ResolveAdditionalKernel32Function("FindFirstFileA", OriginalFindFirstFileA);
    auto OriginalFindNextFileA = ResolveKernelBaseFunction("FindNextFileA", FindNextFileA);
    auto Kernel32FindNextFileA = ResolveAdditionalKernel32Function("FindNextFileA", OriginalFindNextFileA);
    auto OriginalCopyFileA = ResolveKernelBaseFunction("CopyFileA", CopyFileA);
    auto Kernel32CopyFileA = ResolveAdditionalKernel32Function("CopyFileA", OriginalCopyFileA);
    auto OriginalDeleteFileA = ResolveKernelBaseFunction("DeleteFileA", DeleteFileA);
    auto Kernel32DeleteFileA = ResolveAdditionalKernel32Function("DeleteFileA", OriginalDeleteFileA);
    auto OriginalRemoveDirectoryA = ResolveKernelBaseFunction("RemoveDirectoryA", RemoveDirectoryA);
    auto Kernel32RemoveDirectoryA = ResolveAdditionalKernel32Function("RemoveDirectoryA", OriginalRemoveDirectoryA);
    auto OriginalSetCurrentDirectoryA = ResolveKernelBaseFunction("SetCurrentDirectoryA", SetCurrentDirectoryA);
    auto Kernel32SetCurrentDirectoryA = ResolveAdditionalKernel32Function("SetCurrentDirectoryA", OriginalSetCurrentDirectoryA);

    DWORD WINAPI HookGetFileAttributesA(LPCSTR name)
    {
        EmulatedPath path(name);
        return path.Get() ? GetFileAttributesW(path.Get()) : INVALID_FILE_ATTRIBUTES;
    }

    bool ConvertFindData(const WIN32_FIND_DATAW& wide, WIN32_FIND_DATAA* output)
    {
        WIN32_FIND_DATAA result{};
        result.dwFileAttributes = wide.dwFileAttributes;
        result.ftCreationTime = wide.ftCreationTime;
        result.ftLastAccessTime = wide.ftLastAccessTime;
        result.ftLastWriteTime = wide.ftLastWriteTime;
        result.nFileSizeHigh = wide.nFileSizeHigh;
        result.nFileSizeLow = wide.nFileSizeLow;
        result.dwReserved0 = wide.dwReserved0;
        result.dwReserved1 = wide.dwReserved1;
        if (!WideCharToMultiByte(settings.CodePage, 0, wide.cFileName, -1,
            result.cFileName, _countof(result.cFileName), nullptr, nullptr) ||
            !WideCharToMultiByte(settings.CodePage, 0, wide.cAlternateFileName, -1,
                result.cAlternateFileName, _countof(result.cAlternateFileName), nullptr, nullptr))
            return false;
        *output = result;
        return true;
    }

    HANDLE WINAPI HookFindFirstFileA(LPCSTR name, LPWIN32_FIND_DATAA data)
    {
        if (!data) { SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
        EmulatedPath path(name);
        if (!path.Get()) return INVALID_HANDLE_VALUE;
        WIN32_FIND_DATAW wide{};
        HANDLE search = FindFirstFileW(path.Get(), &wide);
        if (search == INVALID_HANDLE_VALUE) return search;
        if (!ConvertFindData(wide, data))
        {
            DWORD error = GetLastError();
            FindClose(search);
            SetLastError(error);
            return INVALID_HANDLE_VALUE;
        }
        return search;
    }

    BOOL WINAPI HookFindNextFileA(HANDLE search, LPWIN32_FIND_DATAA data)
    {
        if (!data) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        WIN32_FIND_DATAW wide{};
        return FindNextFileW(search, &wide) && ConvertFindData(wide, data);
    }

    BOOL WINAPI HookCopyFileA(LPCSTR existingName, LPCSTR newName, BOOL failIfExists)
    {
        EmulatedPath existingPath(existingName);
        if (!existingPath.Get()) return FALSE;
        EmulatedPath newPath(newName);
        return newPath.Get() && CopyFileW(existingPath.Get(), newPath.Get(), failIfExists);
    }

    BOOL WINAPI HookDeleteFileA(LPCSTR name)
    {
        EmulatedPath path(name);
        return path.Get() && DeleteFileW(path.Get());
    }

    BOOL WINAPI HookRemoveDirectoryA(LPCSTR name)
    {
        EmulatedPath path(name);
        return path.Get() && RemoveDirectoryW(path.Get());
    }

    BOOL WINAPI HookSetCurrentDirectoryA(LPCSTR name)
    {
        EmulatedPath path(name);
        return path.Get() && SetCurrentDirectoryW(path.Get());
    }
}

void AttachFileSystemFunctions()
{
    AttachKernelFunction(OriginalGetFileAttributesA, Kernel32GetFileAttributesA, HookGetFileAttributesA);
    AttachKernelFunction(OriginalFindFirstFileA, Kernel32FindFirstFileA, HookFindFirstFileA);
    AttachKernelFunction(OriginalFindNextFileA, Kernel32FindNextFileA, HookFindNextFileA);
    AttachKernelFunction(OriginalCopyFileA, Kernel32CopyFileA, HookCopyFileA);
    AttachKernelFunction(OriginalDeleteFileA, Kernel32DeleteFileA, HookDeleteFileA);
    AttachKernelFunction(OriginalRemoveDirectoryA, Kernel32RemoveDirectoryA, HookRemoveDirectoryA);
    AttachKernelFunction(OriginalSetCurrentDirectoryA, Kernel32SetCurrentDirectoryA, HookSetCurrentDirectoryA);
}

void DetachFileSystemFunctions()
{
    DetachKernelFunction(OriginalGetFileAttributesA, Kernel32GetFileAttributesA, HookGetFileAttributesA);
    DetachKernelFunction(OriginalFindFirstFileA, Kernel32FindFirstFileA, HookFindFirstFileA);
    DetachKernelFunction(OriginalFindNextFileA, Kernel32FindNextFileA, HookFindNextFileA);
    DetachKernelFunction(OriginalCopyFileA, Kernel32CopyFileA, HookCopyFileA);
    DetachKernelFunction(OriginalDeleteFileA, Kernel32DeleteFileA, HookDeleteFileA);
    DetachKernelFunction(OriginalRemoveDirectoryA, Kernel32RemoveDirectoryA, HookRemoveDirectoryA);
    DetachKernelFunction(OriginalSetCurrentDirectoryA, Kernel32SetCurrentDirectoryA, HookSetCurrentDirectoryA);
}
