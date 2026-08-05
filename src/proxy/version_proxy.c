#include "common.h"

//
// version.dll proxy (runtime-forwarding, self-contained).
//
// RecRoom.exe/UnityPlayer.dll import VERSION.dll by name, and the loader searches the app dir before
// System32, so our version.dll in the game root is loaded in their place -- our injection vector
// (DllMain in dllmain.c starts the hook thread). To keep being a working version.dll we must still
// satisfy every export the game asks for.
//
// Rather than ship a renamed copy of the system DLL (version_orig.dll) and use static PE forwarders,
// each export here is a thin wrapper that lazily loads the REAL system version.dll -- by FULL PATH,
// so it never recurses back into us -- and calls through. Result: a single self-contained version.dll
// with nothing extra to ship, which is less confusing for users.
//
// Only UnityPlayer.dll imports version.dll here, and only GetFileVersionInfoA/SizeA + VerQueryValueA,
// but we export the full set faithfully.
//
// We can't name these functions the same as the Win32 APIs (the SDK headers declare them dllimport,
// which conflicts with dllexport), so they get my_ names and are exported under the real names via
// linker /export aliases below. Aliases (no dot) reference our local symbols; they are NOT forwarders.

static volatile HMODULE g_real;

// Load (once) the genuine system version.dll by absolute path so app-dir search can't loop to us.
static HMODULE RealVersion(void)
{
    HMODULE h = g_real;
    if (h) return h;

    wchar_t path[MAX_PATH];
    UINT n = GetSystemDirectoryW(path, MAX_PATH);
    if (n == 0 || n > MAX_PATH - 16) return NULL;
    lstrcatW(path, L"\\version.dll");

    HMODULE loaded = LoadLibraryW(path);
    HMODULE prev = (HMODULE)InterlockedCompareExchangePointer((volatile PVOID *)&g_real, loaded, NULL);
    if (prev) { if (loaded) FreeLibrary(loaded); return prev; }   // lost the race
    return loaded;
}

static FARPROC Proc(const char *name)
{
    HMODULE h = RealVersion();
    return h ? GetProcAddress(h, name) : NULL;
}

// One wrapper per export. The static function-pointer cache is a benign race (GetProcAddress is
// idempotent). A NULL real proc (system DLL missing) degrades to a harmless zero/FALSE return.

BOOL WINAPI my_GetFileVersionInfoA(LPCSTR f, DWORD h, DWORD len, LPVOID data)
{
    typedef BOOL (WINAPI *F)(LPCSTR, DWORD, DWORD, LPVOID);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoA");
    return fn ? fn(f, h, len, data) : FALSE;
}

BOOL WINAPI my_GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD len, LPVOID data)
{
    typedef BOOL (WINAPI *F)(LPCWSTR, DWORD, DWORD, LPVOID);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoW");
    return fn ? fn(f, h, len, data) : FALSE;
}

BOOL WINAPI my_GetFileVersionInfoExA(DWORD flags, LPCSTR f, DWORD h, DWORD len, LPVOID data)
{
    typedef BOOL (WINAPI *F)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoExA");
    return fn ? fn(flags, f, h, len, data) : FALSE;
}

BOOL WINAPI my_GetFileVersionInfoExW(DWORD flags, LPCWSTR f, DWORD h, DWORD len, LPVOID data)
{
    typedef BOOL (WINAPI *F)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoExW");
    return fn ? fn(flags, f, h, len, data) : FALSE;
}

DWORD WINAPI my_GetFileVersionInfoSizeA(LPCSTR f, LPDWORD h)
{
    typedef DWORD (WINAPI *F)(LPCSTR, LPDWORD);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoSizeA");
    return fn ? fn(f, h) : 0;
}

DWORD WINAPI my_GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h)
{
    typedef DWORD (WINAPI *F)(LPCWSTR, LPDWORD);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoSizeW");
    return fn ? fn(f, h) : 0;
}

DWORD WINAPI my_GetFileVersionInfoSizeExA(DWORD flags, LPCSTR f, LPDWORD h)
{
    typedef DWORD (WINAPI *F)(DWORD, LPCSTR, LPDWORD);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoSizeExA");
    return fn ? fn(flags, f, h) : 0;
}

DWORD WINAPI my_GetFileVersionInfoSizeExW(DWORD flags, LPCWSTR f, LPDWORD h)
{
    typedef DWORD (WINAPI *F)(DWORD, LPCWSTR, LPDWORD);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoSizeExW");
    return fn ? fn(flags, f, h) : 0;
}

BOOL WINAPI my_VerQueryValueA(LPCVOID block, LPCSTR sub, LPVOID *buf, PUINT len)
{
    typedef BOOL (WINAPI *F)(LPCVOID, LPCSTR, LPVOID *, PUINT);
    static F fn; if (!fn) fn = (F)Proc("VerQueryValueA");
    return fn ? fn(block, sub, buf, len) : FALSE;
}

BOOL WINAPI my_VerQueryValueW(LPCVOID block, LPCWSTR sub, LPVOID *buf, PUINT len)
{
    typedef BOOL (WINAPI *F)(LPCVOID, LPCWSTR, LPVOID *, PUINT);
    static F fn; if (!fn) fn = (F)Proc("VerQueryValueW");
    return fn ? fn(block, sub, buf, len) : FALSE;
}

DWORD WINAPI my_VerFindFileA(DWORD flags, LPCSTR file, LPCSTR win, LPCSTR app,
                             LPSTR cur, PUINT curLen, LPSTR dest, PUINT destLen)
{
    typedef DWORD (WINAPI *F)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    static F fn; if (!fn) fn = (F)Proc("VerFindFileA");
    return fn ? fn(flags, file, win, app, cur, curLen, dest, destLen) : 0;
}

DWORD WINAPI my_VerFindFileW(DWORD flags, LPCWSTR file, LPCWSTR win, LPCWSTR app,
                             LPWSTR cur, PUINT curLen, LPWSTR dest, PUINT destLen)
{
    typedef DWORD (WINAPI *F)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    static F fn; if (!fn) fn = (F)Proc("VerFindFileW");
    return fn ? fn(flags, file, win, app, cur, curLen, dest, destLen) : 0;
}

DWORD WINAPI my_VerInstallFileA(DWORD flags, LPCSTR src, LPCSTR dst, LPCSTR srcDir,
                                LPCSTR dstDir, LPCSTR curDir, LPSTR tmp, PUINT tmpLen)
{
    typedef DWORD (WINAPI *F)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    static F fn; if (!fn) fn = (F)Proc("VerInstallFileA");
    return fn ? fn(flags, src, dst, srcDir, dstDir, curDir, tmp, tmpLen) : 0;
}

DWORD WINAPI my_VerInstallFileW(DWORD flags, LPCWSTR src, LPCWSTR dst, LPCWSTR srcDir,
                                LPCWSTR dstDir, LPCWSTR curDir, LPWSTR tmp, PUINT tmpLen)
{
    typedef DWORD (WINAPI *F)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    static F fn; if (!fn) fn = (F)Proc("VerInstallFileW");
    return fn ? fn(flags, src, dst, srcDir, dstDir, curDir, tmp, tmpLen) : 0;
}

DWORD WINAPI my_VerLanguageNameA(DWORD lang, LPSTR buf, DWORD size)
{
    typedef DWORD (WINAPI *F)(DWORD, LPSTR, DWORD);
    static F fn; if (!fn) fn = (F)Proc("VerLanguageNameA");
    return fn ? fn(lang, buf, size) : 0;
}

DWORD WINAPI my_VerLanguageNameW(DWORD lang, LPWSTR buf, DWORD size)
{
    typedef DWORD (WINAPI *F)(DWORD, LPWSTR, DWORD);
    static F fn; if (!fn) fn = (F)Proc("VerLanguageNameW");
    return fn ? fn(lang, buf, size) : 0;
}

// Undocumented; not imported by anything in this game. Faithful passthrough with a best-effort
// signature (never actually called here).
BOOL WINAPI my_GetFileVersionInfoByHandle(int a, HANDLE b, DWORD c, LPVOID d)
{
    typedef BOOL (WINAPI *F)(int, HANDLE, DWORD, LPVOID);
    static F fn; if (!fn) fn = (F)Proc("GetFileVersionInfoByHandle");
    return fn ? fn(a, b, c, d) : FALSE;
}

// Export each under its real name (alias to our local my_ symbol; not a forwarder).
#pragma comment(linker, "/export:GetFileVersionInfoA=my_GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoW=my_GetFileVersionInfoW")
#pragma comment(linker, "/export:GetFileVersionInfoExA=my_GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=my_GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=my_GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=my_GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=my_GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=my_GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=my_GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:VerQueryValueA=my_VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=my_VerQueryValueW")
#pragma comment(linker, "/export:VerFindFileA=my_VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=my_VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=my_VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=my_VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=my_VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=my_VerLanguageNameW")
