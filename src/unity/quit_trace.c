#include "common.h"
#include "quit_trace.h"
#include "logger.h"
#include "detour.h"
#include "config.h"

//
// Application.Quit tracer / blocker.
//
// The client boots fully (login, avatar, Photon spawn, title screen) and then shuts itself down at
// ~11 s of game time. Player.log's last line is "PhotonNetwork.Disconnect() called!" with no reason
// logged, and the api/PlayerReporting/v1/referee POST that looked like the trigger actually lands
// ~3 s AFTER the shutdown starts -- it is part of the shutdown flush, not its cause. So something
// calls UnityEngine.Application.Quit() and nothing tells us who.
//
// This detours both Quit overloads to log the CALLER's return address, which maps straight back to
// a method via il2cpp-tools/whatis.py (subtract the logged GameAssembly base). With
// `blockQuit` set in redirector.json the hook also swallows the shutdown by simply returning, which
// both confirms causation and -- if the quit is a spurious anti-cheat/telemetry reaction rather
// than a real fatal condition -- keeps the client alive.
//
// Replace-only detours (we never call the original), so no trampoline is needed and a complex
// prologue can't be mis-decoded -- same reasoning as ssl_patch.c.
//
// RVAs from the Cpp2IL dump for build 2025-04-29 (RecRoom_Info/Code/2025-04-29_02-57-34):
//   UnityEngine.Application$$Quit    0x3EA5FA0   (Quit(), 0 params)
//   UnityEngine.Application$$Quit    0x3EA5FE0   (Quit(int exitCode))
// GameAssembly.dll on this build has NO export table, so the il2cpp reflection API is unreachable
// and hardcoded RVAs are the only option (see CLAUDE.md / ssl_patch.c).
//
#define APP_QUIT_RVA      0x3EA5FA0
#define APP_QUIT_INT_RVA  0x3EA5FE0

static BYTE backup_quit[14];
static BYTE backup_quit_int[14];

static uintptr_t g_gaBase;

// Log the caller as GA+RVA so whatis.py can name it, plus a few stack slots -- the immediate
// return address is often a compiler-generated wrapper, and the real decision site is a frame or
// two up.
static void LogQuitCaller(const char *which, int exitCode, void *retAddr)
{
    uintptr_t ra = (uintptr_t)retAddr;
    if (g_gaBase && ra >= g_gaBase)
        Log("[QUIT] %s(exitCode=%d) called from GA+0x%llX", which, exitCode,
            (unsigned long long)(ra - g_gaBase));
    else
        Log("[QUIT] %s(exitCode=%d) called from %p", which, exitCode, retAddr);

    Log("[QUIT] blockQuit=%d -- %s", block_quit, block_quit ? "SUPPRESSING shutdown" : "allowing shutdown");
}

//
// il2cpp static methods still receive MethodInfo* -- Quit() takes it in RCX, Quit(int) takes the
// int in RCX and MethodInfo* in RDX. Both return void, so returning here simply skips the quit.
//
static void ReplQuit(void *methodInfo)
{
    (void)methodInfo;
    LogQuitCaller("Application.Quit", 0, _ReturnAddress());
    if (block_quit) return;
    // Not blocking: fall through to a plain return anyway. We are a replace-only detour, so the
    // real Quit body is unreachable from here -- "allow" is implemented by not installing the hook
    // at all (see PatchQuitTrace), never by reaching this line.
}

static void ReplQuitInt(int exitCode, void *methodInfo)
{
    (void)methodInfo;
    LogQuitCaller("Application.Quit", exitCode, _ReturnAddress());
    if (block_quit) return;
}

// Spin until the byte at `p` looks like decrypted code rather than a zero/int3 fill (the packer
// decrypts .text shortly after the module maps).
static void WaitForCode(const BYTE *p)
{
    for (int i = 0; i < 600; i++)   // ~60s cap
    {
        BYTE b = p[0];
        if (b != 0x00 && b != 0xCC) return;
        Sleep(100);
    }
}

void PatchQuitTrace(void)
{
    HMODULE ga = NULL;
    while (!ga)
    {
        ga = GetModuleHandleA("GameAssembly.dll");
        if (!ga) Sleep(100);
    }
    g_gaBase = (uintptr_t)ga;
    Log("[QUIT] GameAssembly.dll at %p (map callers with il2cpp-tools/whatis.py)", ga);

    BYTE *q  = (BYTE *)ga + APP_QUIT_RVA;
    BYTE *qi = (BYTE *)ga + APP_QUIT_INT_RVA;
    WaitForCode(q);
    WaitForCode(qi);
    Log("[QUIT] Application.Quit code=%p prologue=%02X %02X %02X %02X", q, q[0], q[1], q[2], q[3]);
    Log("[QUIT] Application.Quit(int) code=%p prologue=%02X %02X %02X %02X", qi, qi[0], qi[1], qi[2], qi[3]);

    if (InstallDetour(q, ReplQuit, backup_quit, NULL))
        Log("[QUIT] tracer installed on Application.Quit()");
    else
        Log("[QUIT] FAILED to hook Application.Quit()");

    if (InstallDetour(qi, ReplQuitInt, backup_quit_int, NULL))
        Log("[QUIT] tracer installed on Application.Quit(int)");
    else
        Log("[QUIT] FAILED to hook Application.Quit(int)");

    HookProcessExit();
}

//
// ---------------------------------------------------------------------------------------------
// Native process-exit tracer.
//
// The managed Application.Quit hooks above never fire, so the session is NOT ended by Unity's
// managed shutdown path. Something tears the process down natively instead. These call-through
// hooks on the two kernel32 exits log who did it (and with what code) and then proceed normally, so
// behaviour is unchanged -- purely a witness.
//
// ExitProcess is the clean path (Unity's player calls it after its main loop returns);
// TerminateProcess is the abrupt one a watchdog would use. Which of the two fires -- and whether the
// caller is UnityPlayer.dll or GameAssembly.dll -- distinguishes "Unity decided to shut down" from
// "something killed us".
// ---------------------------------------------------------------------------------------------
//

typedef void  (WINAPI *exitprocess_t)(UINT);
typedef BOOL  (WINAPI *terminateprocess_t)(HANDLE, UINT);

static exitprocess_t      real_ExitProcess;
static terminateprocess_t real_TerminateProcess;
static BYTE backup_exitproc[24];
static BYTE backup_termproc[24];

static uintptr_t g_upBase, g_upEnd;

// Name an address as GA+RVA / UP+RVA so the caller is identifiable without a debugger.
static void SymAddr(uintptr_t a, char *buf, size_t n)
{
    MODULEINFO mi;
    if (!g_upBase)
    {
        HMODULE up = GetModuleHandleA("UnityPlayer.dll");
        if (up && GetModuleInformation(GetCurrentProcess(), up, &mi, sizeof(mi)))
            { g_upBase = (uintptr_t)mi.lpBaseOfDll; g_upEnd = g_upBase + mi.SizeOfImage; }
    }
    if (g_gaBase && a >= g_gaBase && a < g_gaBase + 0x10000000)
        sprintf_s(buf, n, "GA+0x%llX", (unsigned long long)(a - g_gaBase));
    else if (g_upBase && a >= g_upBase && a < g_upEnd)
        sprintf_s(buf, n, "UP+0x%llX", (unsigned long long)(a - g_upBase));
    else
        sprintf_s(buf, n, "%llX", (unsigned long long)a);
}

static void WINAPI HookExitProcess(UINT code)
{
    char s[64]; SymAddr((uintptr_t)_ReturnAddress(), s, sizeof(s));
    Log("[QUIT] *** ExitProcess(%u) called from %s ***", code, s);
    real_ExitProcess(code);
}

static BOOL WINAPI HookTerminateProcess(HANDLE proc, UINT code)
{
    // Only interesting when it targets US (the game also spawns/kills helper processes).
    if (proc == GetCurrentProcess() || GetProcessId(proc) == GetCurrentProcessId())
    {
        char s[64]; SymAddr((uintptr_t)_ReturnAddress(), s, sizeof(s));
        Log("[QUIT] *** TerminateProcess(SELF, %u) called from %s ***", code, s);
    }
    return real_TerminateProcess(proc, code);
}

void HookProcessExit(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) { Log("[QUIT] kernel32 not found -- no exit tracer"); return; }

    void *ep = (void *)GetProcAddress(k32, "ExitProcess");
    void *tp = (void *)GetProcAddress(k32, "TerminateProcess");

    if (ep && InstallDetour(ep, HookExitProcess, backup_exitproc, (void **)&real_ExitProcess))
        Log("[QUIT] exit tracer installed on ExitProcess");
    else
        Log("[QUIT] FAILED to hook ExitProcess");

    if (tp && InstallDetour(tp, HookTerminateProcess, backup_termproc, (void **)&real_TerminateProcess))
        Log("[QUIT] exit tracer installed on TerminateProcess");
    else
        Log("[QUIT] FAILED to hook TerminateProcess");
}
