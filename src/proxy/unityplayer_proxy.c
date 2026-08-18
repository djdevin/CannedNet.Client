#include "common.h"

//
// UnityPlayer.dll proxy -- loader vector for the recflare-client-unstable build.
//
// This build defeats every app-dir *System32* plant (RecRoom.exe.dll pre-loads the real
// wintrust/bcrypt/crypt32 by full path) AND never loads the DXGIDisplays plugin in this launch mode, so
// those vectors are dead. But UnityPlayer.dll is app-local (game root, no System32 equivalent) and
// RecRoom.exe.dll MUST LoadLibrary it to call UnityMain -- the earliest engine entry, before
// GameAssembly.dll. It exports exactly ONE function, UnityMain, so the proxy is a single forwarder.
// There is no anti-cheat in this process (no Referee/EAC ever load), so nothing inspects us.
//
// UnityMain is forwarded to UnityPlayer_orig.dll (a copy of the genuine 29 MB engine, deployed
// alongside us in the game root; different basename, no loop). DllMain (dllmain.c) starts the hook
// thread, then RecRoom.exe.dll's GetProcAddress(UnityMain)+call flows through us into the real engine.
//
// Deploy: rename the real UnityPlayer.dll -> UnityPlayer_orig.dll, drop this in its place.
//
// UnityMain has the WinMain-style signature int(HINSTANCE,HINSTANCE,LPSTR,int) -- four args, so the
// generic 4-pointer thunk forwards it faithfully (x64: RCX/RDX/R8/R9, return in RAX; the caller reads
// the low 32 bits as int). It blocks for the whole game lifetime, exactly as the caller expects.
//

static volatile HMODULE g_real;

static HMODULE RealUnity(void)
{
    HMODULE h = g_real;
    if (h) return h;

    wchar_t path[MAX_PATH];
    HMODULE self = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&RealUnity, &self);
    DWORD n = GetModuleFileNameW(self, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return NULL;
    for (DWORD i = n; i > 0; i--) { if (path[i-1] == L'\\') { path[i] = 0; break; } }
    lstrcatW(path, L"UnityPlayer_orig.dll");

    HMODULE loaded = LoadLibraryW(path);
    HMODULE prev = (HMODULE)InterlockedCompareExchangePointer((volatile PVOID *)&g_real, loaded, NULL);
    if (prev) { if (loaded) FreeLibrary(loaded); return prev; }
    return loaded;
}

typedef void *(*gen_t)(void *, void *, void *, void *);

void *my_UnityMain(void *a, void *b, void *c, void *d)
{
    static gen_t fn;
    if (!fn) { HMODULE h = RealUnity(); fn = h ? (gen_t)GetProcAddress(h, "UnityMain") : NULL; }
    return fn ? fn(a, b, c, d) : NULL;
}

#pragma comment(linker, "/export:UnityMain=my_UnityMain")
