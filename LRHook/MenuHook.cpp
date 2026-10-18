#include <Windows.h>
#include <detours.h>
#include <cstddef>
#include <climits>
#include <cstring>
#include "LRHookFunc.h"
#include "MenuHook.h"

namespace
{
    auto OriginalGetMenuStringA = GetMenuStringA;
    auto OriginalGetMenuItemInfoA = GetMenuItemInfoA;
    auto OriginalSetMenuItemInfoA = SetMenuItemInfoA;
    auto OriginalInsertMenuItemA = InsertMenuItemA;
    auto OriginalAppendMenuA = AppendMenuA;
    auto OriginalInsertMenuA = InsertMenuA;
    auto OriginalModifyMenuA = ModifyMenuA;
    auto OriginalLoadMenuA = LoadMenuA;
    auto OriginalLoadStringA = LoadStringA;

    class MenuBuffer
    {
        LPWSTR value = nullptr;
    public:
        ~MenuBuffer()
        {
            DWORD error = GetLastError();
            if (value) HeapFree(GetProcessHeap(), 0, value);
            SetLastError(error);
        }
        bool Allocate(size_t count)
        {
            if (count > SIZE_MAX / sizeof(WCHAR))
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return false;
            }
            value = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count * sizeof(WCHAR)));
            if (!value) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return value != nullptr;
        }
        bool FromAnsi(LPCSTR text)
        {
            int count = MultiByteToWideChar(settings.CodePage, 0, text, -1, nullptr, 0);
            return count > 0 && Allocate(count) &&
                MultiByteToWideChar(settings.CodePage, 0, text, -1, value, count) > 0;
        }
        LPWSTR Get() const { return value; }
        MenuBuffer() = default;
        MenuBuffer(const MenuBuffer&) = delete;
        MenuBuffer& operator=(const MenuBuffer&) = delete;
    };

    // A APIs count output bytes. Query the full length, then shorten the Unicode
    // prefix if necessary so truncation never leaves half a DBCS/UTF-8 character.
    int CopyMenuText(LPCWSTR text, int length, LPSTR output, UINT capacity)
    {
        if (length == 0)
        {
            if (output && capacity) output[0] = '\0';
            return 0;
        }
        int bytes = WideCharToMultiByte(settings.CodePage, 0, text, length, nullptr, 0, nullptr, nullptr);
        if (!bytes) return -1;
        if (!output || !capacity) return bytes;
        int available = capacity > INT_MAX ? INT_MAX : static_cast<int>(capacity - 1);
        if (bytes > available)
        {
            int low = 0, high = length;
            while (low < high)
            {
                int mid = low + (high - low + 1) / 2;
                int needed = WideCharToMultiByte(settings.CodePage, 0, text, mid, nullptr, 0, nullptr, nullptr);
                if (needed && needed <= available) low = mid;
                else high = mid - 1;
            }
            length = low;
            if (length > 0 && IS_HIGH_SURROGATE(text[length - 1]) && IS_LOW_SURROGATE(text[length])) --length;
        }
        int copied = length ? WideCharToMultiByte(settings.CodePage, 0, text, length,
            output, available, nullptr, nullptr) : 0;
        if (length && !copied) return -1;
        output[copied] = '\0';
        return copied;
    }

    int WINAPI HookGetMenuStringA(HMENU menu, UINT item, LPSTR output, int capacity, UINT flags)
    {
        if (capacity < 0) return OriginalGetMenuStringA(menu, item, output, capacity, flags);
        int length = GetMenuStringW(menu, item, nullptr, 0, flags);
        if (!length)
        {
            if (output && capacity) output[0] = '\0';
            return 0;
        }
        MenuBuffer text;
        if (!text.Allocate(static_cast<size_t>(length) + 1)) return 0;
        length = GetMenuStringW(menu, item, text.Get(), length + 1, flags);
        int copied = CopyMenuText(text.Get(), length, output, capacity);
        return copied < 0 ? 0 : copied;
    }

    bool ValidItemInfo(LPCMENUITEMINFOA info)
    {
        // The old structure stops before hbmpItem. Never read/write a full
        // current structure when a caller supplied only the legacy prefix.
        return info && (info->cbSize == sizeof(MENUITEMINFOA) ||
            info->cbSize == offsetof(MENUITEMINFOA, hbmpItem));
    }

    bool HasItemString(const MENUITEMINFOW& info)
    {
        if (info.fMask & MIIM_STRING) return true;
        return (info.fMask & MIIM_TYPE) && !(info.fType & (MFT_BITMAP | MFT_OWNERDRAW | MFT_SEPARATOR));
    }

    BOOL WINAPI HookGetMenuItemInfoA(HMENU menu, UINT item, BOOL byPosition, LPMENUITEMINFOA info)
    {
        if (!ValidItemInfo(info)) return OriginalGetMenuItemInfoA(menu, item, byPosition, info);
        static_assert(sizeof(MENUITEMINFOA) == sizeof(MENUITEMINFOW), "Menu structure layouts must match");
        MENUITEMINFOW wide{};
        std::memcpy(&wide, info, info->cbSize);
        if (!(wide.fMask & (MIIM_STRING | MIIM_TYPE)))
        {
            if (!GetMenuItemInfoW(menu, item, byPosition, &wide)) return FALSE;
            std::memcpy(info, &wide, info->cbSize);
            return TRUE;
        }
        LPSTR output = info->dwTypeData;
        UINT capacity = info->cch;
        wide.dwTypeData = nullptr;
        wide.cch = 0;
        if (!GetMenuItemInfoW(menu, item, byPosition, &wide)) return FALSE;
        if (HasItemString(wide))
        {
            if (wide.cch >= INT_MAX) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
            MenuBuffer text;
            UINT count = wide.cch + 1;
            if (!text.Allocate(count)) return FALSE;
            wide.dwTypeData = text.Get();
            wide.cch = count;
            if (!GetMenuItemInfoW(menu, item, byPosition, &wide)) return FALSE;
            int copied = CopyMenuText(text.Get(), static_cast<int>(wide.cch), output, capacity);
            if (copied < 0) return FALSE;
            wide.cch = copied;
            wide.dwTypeData = reinterpret_cast<LPWSTR>(output);
        }
        std::memcpy(info, &wide, info->cbSize);
        return TRUE;
    }

    template<typename Function>
    BOOL WriteItem(Function function, HMENU menu, UINT item, BOOL byPosition, LPCMENUITEMINFOA info)
    {
        MENUITEMINFOW wide{};
        std::memcpy(&wide, info, info->cbSize);
        MenuBuffer text;
        if (HasItemString(wide) && info->dwTypeData)
        {
            if (!text.FromAnsi(info->dwTypeData)) return FALSE;
            wide.dwTypeData = text.Get();
        }
        return function(menu, item, byPosition, &wide);
    }

    BOOL WINAPI HookSetMenuItemInfoA(HMENU menu, UINT item, BOOL byPosition, LPCMENUITEMINFOA info)
    {
        if (!ValidItemInfo(info)) return OriginalSetMenuItemInfoA(menu, item, byPosition, info);
        return WriteItem(SetMenuItemInfoW, menu, item, byPosition, info);
    }

    BOOL WINAPI HookInsertMenuItemA(HMENU menu, UINT item, BOOL byPosition, LPCMENUITEMINFOA info)
    {
        if (!ValidItemInfo(info)) return OriginalInsertMenuItemA(menu, item, byPosition, info);
        return WriteItem(InsertMenuItemW, menu, item, byPosition, info);
    }

    template<typename Function>
    BOOL ChangeItem(Function function, HMENU menu, UINT item, UINT flags, UINT_PTR id, LPCSTR value)
    {
        // Owner-draw values and bitmap handles are opaque data, never strings.
        if (!value || (flags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR)))
            return function(menu, item, flags, id, reinterpret_cast<LPCWSTR>(value));
        MenuBuffer text;
        return text.FromAnsi(value) && function(menu, item, flags, id, text.Get());
    }

    BOOL WINAPI HookAppendMenuA(HMENU menu, UINT flags, UINT_PTR id, LPCSTR value)
    {
        // Adapt AppendMenu's shorter signature to the shared conversion path.
        return ChangeItem([](HMENU h, UINT, UINT f, UINT_PTR i, LPCWSTR s) { return AppendMenuW(h, f, i, s); },
            menu, 0, flags, id, value);
    }

    BOOL WINAPI HookInsertMenuA(HMENU menu, UINT item, UINT flags, UINT_PTR id, LPCSTR value)
    {
        return ChangeItem(InsertMenuW, menu, item, flags, id, value);
    }

    BOOL WINAPI HookModifyMenuA(HMENU menu, UINT item, UINT flags, UINT_PTR id, LPCSTR value)
    {
        return ChangeItem(ModifyMenuW, menu, item, flags, id, value);
    }

    HMENU WINAPI HookLoadMenuA(HINSTANCE instance, LPCSTR name)
    {
        if (IS_INTRESOURCE(name)) return LoadMenuW(instance, reinterpret_cast<LPCWSTR>(name));
        MenuBuffer text;
        return text.FromAnsi(name) ? LoadMenuW(instance, text.Get()) : nullptr;
    }

    int WINAPI HookLoadStringA(HINSTANCE instance, UINT id, LPSTR output, int capacity)
    {
        if (!output || capacity <= 0) return OriginalLoadStringA(instance, id, output, capacity);
        LPCWSTR text = nullptr;
        // The W-only zero-capacity mode returns a resource pointer and its counted
        // length, preserving embedded NULs without an arbitrary temporary limit.
        int length = LoadStringW(instance, id, reinterpret_cast<LPWSTR>(&text), 0);
        int copied = CopyMenuText(text, length, output, capacity);
        return copied < 0 ? 0 : copied;
    }
}

void AttachMenuFunctions()
{
    DetourAttach(&(PVOID&)OriginalGetMenuStringA, HookGetMenuStringA);
    DetourAttach(&(PVOID&)OriginalGetMenuItemInfoA, HookGetMenuItemInfoA);
    DetourAttach(&(PVOID&)OriginalSetMenuItemInfoA, HookSetMenuItemInfoA);
    DetourAttach(&(PVOID&)OriginalInsertMenuItemA, HookInsertMenuItemA);
    DetourAttach(&(PVOID&)OriginalAppendMenuA, HookAppendMenuA);
    DetourAttach(&(PVOID&)OriginalInsertMenuA, HookInsertMenuA);
    DetourAttach(&(PVOID&)OriginalModifyMenuA, HookModifyMenuA);
    DetourAttach(&(PVOID&)OriginalLoadMenuA, HookLoadMenuA);
    DetourAttach(&(PVOID&)OriginalLoadStringA, HookLoadStringA);
}

void DetachMenuFunctions()
{
    DetourDetach(&(PVOID&)OriginalLoadStringA, HookLoadStringA);
    DetourDetach(&(PVOID&)OriginalLoadMenuA, HookLoadMenuA);
    DetourDetach(&(PVOID&)OriginalModifyMenuA, HookModifyMenuA);
    DetourDetach(&(PVOID&)OriginalInsertMenuA, HookInsertMenuA);
    DetourDetach(&(PVOID&)OriginalAppendMenuA, HookAppendMenuA);
    DetourDetach(&(PVOID&)OriginalInsertMenuItemA, HookInsertMenuItemA);
    DetourDetach(&(PVOID&)OriginalSetMenuItemInfoA, HookSetMenuItemInfoA);
    DetourDetach(&(PVOID&)OriginalGetMenuItemInfoA, HookGetMenuItemInfoA);
    DetourDetach(&(PVOID&)OriginalGetMenuStringA, HookGetMenuStringA);
}
