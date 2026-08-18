#include "common.h"

//
// DXGIDisplays.dll proxy -- loader vector for the recflare-client-unstable build.
//
// This build hardens against app-dir DLL planting: RecRoom.exe.dll pre-loads the real System32 crypto
// DLLs (wintrust/bcrypt/crypt32) by full path, so none of those static-import proxies ever win (all
// three were observed loading from C:\Windows\System32). What the loader CANNOT redirect to System32 is
// a Rec Room first-party Unity plugin: UnityPlayer LoadLibrary's DXGIDisplays.dll from
// RecRoom_Data\Plugins\x86_64 by that path, so replacing the file there is a legitimate in-process load
// of our code -- no injection, no foreign thread. DXGIDisplays is enumerated during display/screen-mode
// setup at engine startup (early and unconditional, well before the RecNet connection at ~5 s), which
// is exactly when we need to be resident. (RRTexture.dll loads too late -- only on the first texture-
// compression call, gated behind server content the client never fetches.)
//
// Its 15 exports are forwarded to DXGIDisplays_orig.dll (a copy of the genuine plugin, deployed
// alongside us in the same Plugins dir; different basename, so no loop). DllMain (dllmain.c) starts the
// hook thread -- the full redirector runs unchanged from here.
//
// Deploy: rename the real Plugins\x86_64\DXGIDisplays.dll -> DXGIDisplays_orig.dll, drop this in place.
//
// The exports all take <=4 args and are pure passthrough (the game calls them for real display data),
// so a generic 4-pointer thunk forwards them faithfully: on x64 the first four args are RCX/RDX/R8/R9
// and the return is RAX. We never inspect the args.
//

static volatile HMODULE g_real;

// Load (once) the genuine plugin, renamed DXGIDisplays_orig.dll, from THIS module's own directory
// (Plugins\x86_64) by full path so the plugin search can't loop back into us.
static HMODULE RealDxgi(void)
{
    HMODULE h = g_real;
    if (h) return h;

    wchar_t path[MAX_PATH];
    HMODULE self = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&RealDxgi, &self);
    DWORD n = GetModuleFileNameW(self, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return NULL;
    for (DWORD i = n; i > 0; i--) { if (path[i-1] == L'\\') { path[i] = 0; break; } }
    lstrcatW(path, L"DXGIDisplays_orig.dll");

    HMODULE loaded = LoadLibraryW(path);
    HMODULE prev = (HMODULE)InterlockedCompareExchangePointer((volatile PVOID *)&g_real, loaded, NULL);
    if (prev) { if (loaded) FreeLibrary(loaded); return prev; }
    return loaded;
}

typedef void *(*gen_t)(void *, void *, void *, void *);
static gen_t P(const char *name) { HMODULE h = RealDxgi(); return h ? (gen_t)GetProcAddress(h, name) : NULL; }

#define FWD(NAME) \
    void *my_##NAME(void *a, void *b, void *c, void *d) { \
        static gen_t fn; if (!fn) fn = P(#NAME); return fn ? fn(a,b,c,d) : NULL; }

FWD(Finalize) FWD(GetDisplayBottom) FWD(GetDisplayCount) FWD(GetDisplayDpiX) FWD(GetDisplayDpiY)
FWD(GetDisplayHeight) FWD(GetDisplayLeft) FWD(GetDisplayRight) FWD(GetDisplayRotation)
FWD(GetDisplayTop) FWD(GetDisplayWidth) FWD(Initialize) FWD(IsDisplayPrimary) FWD(IsInitialized)
FWD(LinkUnityDebugCallback)

#pragma comment(linker, "/export:Finalize=my_Finalize")
#pragma comment(linker, "/export:GetDisplayBottom=my_GetDisplayBottom")
#pragma comment(linker, "/export:GetDisplayCount=my_GetDisplayCount")
#pragma comment(linker, "/export:GetDisplayDpiX=my_GetDisplayDpiX")
#pragma comment(linker, "/export:GetDisplayDpiY=my_GetDisplayDpiY")
#pragma comment(linker, "/export:GetDisplayHeight=my_GetDisplayHeight")
#pragma comment(linker, "/export:GetDisplayLeft=my_GetDisplayLeft")
#pragma comment(linker, "/export:GetDisplayRight=my_GetDisplayRight")
#pragma comment(linker, "/export:GetDisplayRotation=my_GetDisplayRotation")
#pragma comment(linker, "/export:GetDisplayTop=my_GetDisplayTop")
#pragma comment(linker, "/export:GetDisplayWidth=my_GetDisplayWidth")
#pragma comment(linker, "/export:Initialize=my_Initialize")
#pragma comment(linker, "/export:IsDisplayPrimary=my_IsDisplayPrimary")
#pragma comment(linker, "/export:IsInitialized=my_IsInitialized")
#pragma comment(linker, "/export:LinkUnityDebugCallback=my_LinkUnityDebugCallback")
