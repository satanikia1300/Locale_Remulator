#include <Windows.h>
#include <detours.h>
#include <climits>
#include <cstring>
#include "LRHookFunc.h"
#include "TextHook.h"

namespace
{
    auto OriginalDrawTextW = DrawTextW;
    auto OriginalDrawTextExW = DrawTextExW;
    auto OriginalDrawTextExA = DrawTextExA;
    auto OriginalTextOutW = TextOutW;
    auto OriginalTextOutA = TextOutA;
    auto OriginalExtTextOutW = ExtTextOutW;
    auto OriginalExtTextOutA = ExtTextOutA;
    auto OriginalGetTextExtentPoint32W = GetTextExtentPoint32W;
    auto OriginalGetTextExtentPoint32A = GetTextExtentPoint32A;
    auto OriginalGetTextExtentExPointW = GetTextExtentExPointW;
    auto OriginalGetTextExtentExPointA = GetTextExtentExPointA;

    struct FontEntry { LOGFONTW source; HFONT replacement; };
    SRWLOCK fontLock = SRWLOCK_INIT;
    FontEntry fonts[16]{};
    // A small process-lifetime cache: cached fonts must remain valid across
    // concurrent paint calls. GDI releases these objects when the process exits.
    HFONT FallbackFont(HDC dc)
    {
        TEXTMETRICW metrics{};
        if (!GetTextMetricsW(dc, &metrics) || (metrics.tmPitchAndFamily & (TMPF_TRUETYPE | TMPF_VECTOR)))
            return nullptr;
        CHARSETINFO charset{};
        if (settings.CodePage != CP_UTF8 &&
            (!TranslateCharsetInfo(reinterpret_cast<DWORD*>(static_cast<ULONG_PTR>(settings.CodePage)), &charset, TCI_SRCCODEPAGE) ||
             charset.ciCharset == metrics.tmCharSet)) return nullptr;
        LOGFONTW source{};
        HFONT current = static_cast<HFONT>(GetCurrentObject(dc, OBJ_FONT));
        if (GetObjectW(current, sizeof(source), &source) != sizeof(source)) return nullptr;
        AcquireSRWLockExclusive(&fontLock);
        FontEntry* empty = nullptr;
        for (auto& entry : fonts)
        {
            if (entry.replacement && !std::memcmp(&entry.source, &source, sizeof(source)))
            {
                HFONT result = entry.replacement;
                ReleaseSRWLockExclusive(&fontLock);
                return result;
            }
            if (!entry.replacement && !empty) empty = &entry;
        }
        HFONT result = nullptr;
        if (empty)
        {
            LOGFONTW replacement = source;
            replacement.lfCharSet = settings.CodePage == CP_UTF8 ? DEFAULT_CHARSET : static_cast<BYTE>(charset.ciCharset);
            replacement.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
            LPCWSTR face = settings.CodePage == 949 ? L"Malgun Gothic" :
                settings.CodePage == 932 ? L"Yu Gothic UI" :
                settings.CodePage == 936 ? L"Microsoft YaHei UI" :
                settings.CodePage == 950 ? L"Microsoft JhengHei UI" : L"Segoe UI";
            lstrcpynW(replacement.lfFaceName, face, LF_FACESIZE);
            result = CreateFontIndirectW(&replacement);
            if (result) { empty->source = source; empty->replacement = result; }
        }
        ReleaseSRWLockExclusive(&fontLock);
        return result;
    }

    class TextFont
    {
        HDC dc;
        HGDIOBJ previous = nullptr;
        void SelectForText(LPCWSTR text, int count)
        {
            if (!text || !count) return;
            for (int n = 0; count < 0 ? text[n] != 0 : n < count; ++n)
                if (text[n] > 0x7F)
                {
                    if (HFONT font = FallbackFont(dc)) previous = SelectObject(dc, font);
                    break;
                }
        }
    public:
        TextFont(HDC target, LPCWSTR text, int count) : dc(target)
        {
            DWORD error = GetLastError();
            SelectForText(text, count);
            SetLastError(error);
        }
        TextFont(HDC target, LPCSTR text, int count) : dc(target)
        {
            DWORD error = GetLastError();
            bool nonAscii = false;
            if (text)
                for (int n = 0; n < count; ++n)
                    if (static_cast<BYTE>(text[n]) > 0x7F) { nonAscii = true; break; }
            TEXTMETRICW metrics{};
            if (nonAscii && GetTextMetricsW(dc, &metrics) &&
                !(metrics.tmPitchAndFamily & (TMPF_TRUETYPE | TMPF_VECTOR)))
            {
                int length = MultiByteToWideChar(settings.CodePage, 0, text, count, nullptr, 0);
                if (length > 0)
                {
                    LPWSTR wide = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0, static_cast<size_t>(length) * sizeof(WCHAR)));
                    if (wide)
                    {
                        if (MultiByteToWideChar(settings.CodePage, 0, text, count, wide, length)) SelectForText(wide, length);
                        HeapFree(GetProcessHeap(), 0, wide);
                    }
                }
            }
            SetLastError(error);
        }
        ~TextFont()
        {
            DWORD error = GetLastError();
            if (previous && previous != HGDI_ERROR) SelectObject(dc, previous);
            SetLastError(error);
        }
        TextFont(const TextFont&) = delete;
        TextFont& operator=(const TextFont&) = delete;
    };

    int WINAPI HookDrawTextW(HDC dc, LPCWSTR text, int count, LPRECT rect, UINT format)
    {
        if (count < -1) return OriginalDrawTextW(dc, text, count, rect, format);
        TextFont font(dc, text, count);
        return OriginalDrawTextW(dc, text, count, rect, format);
    }

    int WINAPI HookDrawTextExW(HDC dc, LPWSTR text, int count, LPRECT rect, UINT format, LPDRAWTEXTPARAMS params)
    {
        if (count < -1) return OriginalDrawTextExW(dc, text, count, rect, format, params);
        TextFont font(dc, text, count);
        return OriginalDrawTextExW(dc, text, count, rect, format, params);
    }

    int WINAPI HookDrawTextExA(HDC dc, LPSTR text, int count, LPRECT rect, UINT format, LPDRAWTEXTPARAMS params)
    {
        if (!text || count < -1) return OriginalDrawTextExA(dc, text, count, rect, format, params);
        int bytes = count == -1 ? lstrlenA(text) : count;
        int length = bytes ? MultiByteToWideChar(settings.CodePage, 0, text, bytes, nullptr, 0) : 0;
        if (bytes && !length) return 0;
        LPWSTR wide = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            (static_cast<size_t>(length) + 5) * sizeof(WCHAR)));
        if (!wide) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
        if (length && !MultiByteToWideChar(settings.CodePage, 0, text, bytes, wide, length))
        {
            DWORD error = GetLastError(); HeapFree(GetProcessHeap(), 0, wide); SetLastError(error); return 0;
        }
        int result;
        {
            TextFont font(dc, wide, length);
            result = OriginalDrawTextExW(dc, wide, length, rect, format, params);
        }
        DWORD error = GetLastError();
        if ((format & DT_MODIFYSTRING) && bytes <= INT_MAX - 4)
            WideCharToMultiByte(settings.CodePage, 0, wide, -1, text, bytes + 4, nullptr, nullptr);
        HeapFree(GetProcessHeap(), 0, wide);
        SetLastError(error);
        return result;
    }

    BOOL WINAPI HookTextOutW(HDC dc, int x, int y, LPCWSTR text, int count)
    {
        // TextOut's count is mandatory; negative values belong to the native
        // error path and must not cause a scan for a terminator.
        if (count < 0) return OriginalTextOutW(dc, x, y, text, count);
        TextFont font(dc, text, count);
        return OriginalTextOutW(dc, x, y, text, count);
    }

    BOOL WINAPI HookTextOutA(HDC dc, int x, int y, LPCSTR text, int count)
    {
        if (count < 0) return OriginalTextOutA(dc, x, y, text, count);
        // Select before GDI shapes the ANSI run and computes its advances.
        TextFont font(dc, text, count);
        return OriginalTextOutA(dc, x, y, text, count);
    }

    BOOL WINAPI HookExtTextOutW(HDC dc, int x, int y, UINT options, const RECT* rect, LPCWSTR text, UINT count, const INT* dx)
    {
        // Glyph IDs belong to the caller's selected font; replacing that font
        // would invalidate the IDs. Empty ETO_OPAQUE fills also pass through.
        if ((options & ETO_GLYPH_INDEX) || !count || count > 8192)
            return OriginalExtTextOutW(dc, x, y, options, rect, text, count, dx);
        TextFont font(dc, text, static_cast<int>(count));
        return OriginalExtTextOutW(dc, x, y, options, rect, text, count, dx);
    }

    BOOL WINAPI HookExtTextOutA(HDC dc, int x, int y, UINT options, const RECT* rect, LPCSTR text, UINT count, const INT* dx)
    {
        if ((options & ETO_GLYPH_INDEX) || !count || count > 8192)
            return OriginalExtTextOutA(dc, x, y, options, rect, text, count, dx);
        TextFont font(dc, text, static_cast<int>(count));
        // Let GDI retain its byte-based lpDx / ETO_PDY conversion semantics.
        return OriginalExtTextOutA(dc, x, y, options, rect, text, count, dx);
    }

    BOOL WINAPI HookGetTextExtentPoint32W(HDC dc, LPCWSTR text, int count, LPSIZE size)
    {
        if (count < 0) return OriginalGetTextExtentPoint32W(dc, text, count, size);
        TextFont font(dc, text, count);
        return OriginalGetTextExtentPoint32W(dc, text, count, size);
    }

    BOOL WINAPI HookGetTextExtentPoint32A(HDC dc, LPCSTR text, int count, LPSIZE size)
    {
        if (count < 0) return OriginalGetTextExtentPoint32A(dc, text, count, size);
        TextFont font(dc, text, count);
        return OriginalGetTextExtentPoint32A(dc, text, count, size);
    }

    BOOL WINAPI HookGetTextExtentExPointW(HDC dc, LPCWSTR text, int count, int maximum, LPINT fit, LPINT dx, LPSIZE size)
    {
        if (count < 0) return OriginalGetTextExtentExPointW(dc, text, count, maximum, fit, dx, size);
        TextFont font(dc, text, count);
        return OriginalGetTextExtentExPointW(dc, text, count, maximum, fit, dx, size);
    }

    BOOL WINAPI HookGetTextExtentExPointA(HDC dc, LPCSTR text, int count, int maximum, LPINT fit, LPINT dx, LPSIZE size)
    {
        if (count < 0) return OriginalGetTextExtentExPointA(dc, text, count, maximum, fit, dx, size);
        TextFont font(dc, text, count);
        return OriginalGetTextExtentExPointA(dc, text, count, maximum, fit, dx, size);
    }

}

void AttachTextFunctions()
{
    DetourAttach(&(PVOID&)OriginalDrawTextW, HookDrawTextW);
    DetourAttach(&(PVOID&)OriginalDrawTextExW, HookDrawTextExW);
    DetourAttach(&(PVOID&)OriginalDrawTextExA, HookDrawTextExA);
    DetourAttach(&(PVOID&)OriginalTextOutW, HookTextOutW);
    DetourAttach(&(PVOID&)OriginalTextOutA, HookTextOutA);
    DetourAttach(&(PVOID&)OriginalExtTextOutW, HookExtTextOutW);
    DetourAttach(&(PVOID&)OriginalExtTextOutA, HookExtTextOutA);
    DetourAttach(&(PVOID&)OriginalGetTextExtentPoint32W, HookGetTextExtentPoint32W);
    DetourAttach(&(PVOID&)OriginalGetTextExtentPoint32A, HookGetTextExtentPoint32A);
    DetourAttach(&(PVOID&)OriginalGetTextExtentExPointW, HookGetTextExtentExPointW);
    DetourAttach(&(PVOID&)OriginalGetTextExtentExPointA, HookGetTextExtentExPointA);
}

void DetachTextFunctions()
{
    DetourDetach(&(PVOID&)OriginalGetTextExtentExPointA, HookGetTextExtentExPointA);
    DetourDetach(&(PVOID&)OriginalGetTextExtentExPointW, HookGetTextExtentExPointW);
    DetourDetach(&(PVOID&)OriginalGetTextExtentPoint32A, HookGetTextExtentPoint32A);
    DetourDetach(&(PVOID&)OriginalGetTextExtentPoint32W, HookGetTextExtentPoint32W);
    DetourDetach(&(PVOID&)OriginalExtTextOutA, HookExtTextOutA);
    DetourDetach(&(PVOID&)OriginalExtTextOutW, HookExtTextOutW);
    DetourDetach(&(PVOID&)OriginalTextOutA, HookTextOutA);
    DetourDetach(&(PVOID&)OriginalTextOutW, HookTextOutW);
    DetourDetach(&(PVOID&)OriginalDrawTextExA, HookDrawTextExA);
    DetourDetach(&(PVOID&)OriginalDrawTextExW, HookDrawTextExW);
    DetourDetach(&(PVOID&)OriginalDrawTextW, HookDrawTextW);
}
