#include "common.h"
#include "logger.h"
#include "crash_handler.h"

//
// Vectored exception handler that logs access violations (0xC0000005) as GameAssembly-relative RVAs so
// the faulting method can be mapped in the Cpp2IL dump. First-chance, non-intrusive: it logs and
// returns EXCEPTION_CONTINUE_SEARCH so the game's own handling is unchanged. The LAST AV logged before
// the process dies is the fatal one.
//

static uintptr_t g_gaBase, g_gaEnd;
static uintptr_t g_upBase, g_upEnd;
static uintptr_t g_rrBase, g_rrEnd;

// Set by the SendRequest hook the first time it runs -- that hook executes on Unity's main thread,
// which is exactly the thread we want to watch for the ~11s stall.
volatile DWORD g_mainThreadId;

static void ResolveModuleRanges(void)
{
    HMODULE ga = GetModuleHandleA("GameAssembly.dll");
    HMODULE up = GetModuleHandleA("UnityPlayer.dll");
    HMODULE rr = GetModuleHandleA("RecRoom.exe.dll");
    MODULEINFO mi;
    if (ga && GetModuleInformation(GetCurrentProcess(), ga, &mi, sizeof(mi)))
        { g_gaBase = (uintptr_t)mi.lpBaseOfDll; g_gaEnd = g_gaBase + mi.SizeOfImage; }
    if (up && GetModuleInformation(GetCurrentProcess(), up, &mi, sizeof(mi)))
        { g_upBase = (uintptr_t)mi.lpBaseOfDll; g_upEnd = g_upBase + mi.SizeOfImage; }
    if (rr && GetModuleInformation(GetCurrentProcess(), rr, &mi, sizeof(mi)))
        { g_rrBase = (uintptr_t)mi.lpBaseOfDll; g_rrEnd = g_rrBase + mi.SizeOfImage; }
}

// Format an address as "GA+0xRVA" / "UP+0xRVA" / "RR+0xRVA" / raw, into buf. RR is the
// Themida-wrapped RecRoom.exe.dll, which is where the fatal faults land -- worth naming.
static void Sym(uintptr_t a, char *buf, size_t n)
{
    if (!g_gaBase) ResolveModuleRanges();
    if (g_gaBase && a >= g_gaBase && a < g_gaEnd)      sprintf_s(buf, n, "GA+0x%llX", (unsigned long long)(a - g_gaBase));
    else if (g_upBase && a >= g_upBase && a < g_upEnd)  sprintf_s(buf, n, "UP+0x%llX", (unsigned long long)(a - g_upBase));
    else if (g_rrBase && a >= g_rrBase && a < g_rrEnd)  sprintf_s(buf, n, "RR+0x%llX", (unsigned long long)(a - g_rrBase));
    else                                                sprintf_s(buf, n, "%llX", (unsigned long long)a);
}

// Structured-exception-safe read: the values we walk to (poisoned/wild pointers) are
// frequently unmapped, so a plain dereference here would just recurse into another AV.
static int SafeReadPtr(uintptr_t addr, uint64_t *out)
{
    __try {
        *out = *(volatile uint64_t *)addr;
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static LONG CALLBACK VehCrash(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // The fatal fault (RecRoom.exe.dll+0x34D7E14) never shows up as an AV in our log, yet WER records
    // it -- so either a different exception code kills us, or it arrives on a path our AV-only filter
    // drops. Log EVERY exception's code + faulting address once, cheaply, so we can see what actually
    // precedes death. Skip the two noisy, benign, self-decrypt guard-page/breakpoint codes Themida
    // raises constantly, and skip C0000005 here (handled in full below) to avoid double-logging.
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != 0x80000001 /* STATUS_GUARD_PAGE_VIOLATION */ &&
        code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP)
    {
        char at[64];
        Sym(ep->ExceptionRecord->ExceptionAddress ? (uintptr_t)ep->ExceptionRecord->ExceptionAddress : 0,
            at, sizeof(at));

        // 0xE06D7363 ('msc') is a C++ throw. Its ExceptionAddress is always KernelBase!RaiseException,
        // which tells us nothing -- what matters is WHO threw. For a C++ throw the ExceptionInformation
        // is [magic, &exception_object, &ThrowInfo], and ThrowInfo lives in the throwing module's
        // rdata, so its address identifies that module. Walk the faulting thread's stack for the first
        // few return addresses that land in a known module -- that is the throw path. This is the
        // event that precedes the fatal RecRoom.exe.dll abort, so its origin is the real lead.
        if (code == 0xE06D7363)
        {
            // These come in bursts; a full stack dump on each would flood the log. Show the detailed
            // walk only a handful of times.
            static volatile LONG cppSeen;
            if (InterlockedIncrement(&cppSeen) > 6) return EXCEPTION_CONTINUE_SEARCH;

            uintptr_t throwInfo = (ep->ExceptionRecord->NumberParameters >= 4)
                                    ? (uintptr_t)ep->ExceptionRecord->ExceptionInformation[3] : 0;
            char ti[64]; Sym(throwInfo, ti, sizeof(ti));
            Log("[CRASH] C++ exception (E06D7363) at %s throwInfo=%s", at, ti);

            uintptr_t rsp = ep->ContextRecord ? (uintptr_t)ep->ContextRecord->Rsp : 0;
            int shown = 0;
            for (int i = 0; i < 40 && shown < 8 && rsp; i++)
            {
                uint64_t v;
                if (!SafeReadPtr(rsp + (uintptr_t)i * 8, &v)) break;
                uintptr_t a = (uintptr_t)v;
                if ((g_gaBase && a >= g_gaBase && a < g_gaEnd) ||
                    (g_upBase && a >= g_upBase && a < g_upEnd) ||
                    (g_rrBase && a >= g_rrBase && a < g_rrEnd))
                {
                    char f[64]; Sym(a, f, sizeof(f));
                    Log("[CRASH]   throw-stack [rsp+0x%X]=%s", i * 8, f);
                    shown++;
                }
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }

        Log("[CRASH] exception code=%08lX at %s (firstChance)", (unsigned long)code, at);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;

    if (!g_gaBase) ResolveModuleRanges();

    PCONTEXT ctx = ep->ContextRecord;
    char at[64], acc[64];
    uintptr_t fault = ep->ExceptionRecord->ExceptionAddress ? (uintptr_t)ep->ExceptionRecord->ExceptionAddress : 0;
    Sym(fault, at, sizeof(at));
    uintptr_t accAddr = (ep->ExceptionRecord->NumberParameters >= 2) ? (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1] : 0;
    uintptr_t accType = (ep->ExceptionRecord->NumberParameters >= 1) ? (uintptr_t)ep->ExceptionRecord->ExceptionInformation[0] : 0;
    Sym(accAddr, acc, sizeof(acc));
    // 0 = read fault, 1 = write fault, 8 = DEP/NX (attempted execute of non-executable page).
    const char *kind = (accType == 8) ? "EXECUTE" : (accType == 1) ? "WRITE" : "READ";

    Log("[CRASH] ACCESS_VIOLATION at %s %s addr=%s (raw fault=%llX access=%llX)",
        at, kind, acc, (unsigned long long)fault, (unsigned long long)accAddr);

    Log("[CRASH]   rax=%llX rbx=%llX rcx=%llX rdx=%llX rsi=%llX rdi=%llX rbp=%llX rsp=%llX",
        (unsigned long long)ctx->Rax, (unsigned long long)ctx->Rbx, (unsigned long long)ctx->Rcx,
        (unsigned long long)ctx->Rdx, (unsigned long long)ctx->Rsi, (unsigned long long)ctx->Rdi,
        (unsigned long long)ctx->Rbp, (unsigned long long)ctx->Rsp);
    Log("[CRASH]   r8=%llX r9=%llX r10=%llX r11=%llX r12=%llX r13=%llX r14=%llX r15=%llX",
        (unsigned long long)ctx->R8, (unsigned long long)ctx->R9, (unsigned long long)ctx->R10,
        (unsigned long long)ctx->R11, (unsigned long long)ctx->R12, (unsigned long long)ctx->R13,
        (unsigned long long)ctx->R14, (unsigned long long)ctx->R15);

    // Walk the FAULTING thread's actual stack (ctx->Rsp), not our own -- CaptureStackBackTrace()
    // here would only see the VEH dispatch frames. When rip itself is the bad address (a call
    // through a corrupt pointer), [rsp] at fault time is the caller's return address.
    for (int i = 0; i < 16; i++)
    {
        uint64_t v;
        if (!SafeReadPtr((uintptr_t)ctx->Rsp + (uintptr_t)i * 8, &v)) break;
        char s[64]; Sym((uintptr_t)v, s, sizeof(s));
        Log("[CRASH]   [rsp+0x%X]=%s", i * 8, s);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void InstallCrashHandler(void)
{
    ResolveModuleRanges();
    AddVectoredExceptionHandler(1, VehCrash);   // 1 = call first
    Log("[CRASH] vectored AV logger installed");
}

//
// ---------------------------------------------------------------------------------------------
// Hang probe.
//
// Player.log stops dead at PhotonNetwork.Disconnect() (~11s of game time) and the process then
// lingers ~20s before aborting, with fault sites that move around (RecRoom.exe.dll+0x34D7E14 /
// +0x34F2AE8 / +0x35FB437, and ucrtbase abort). That pattern says the main thread stops making
// progress and the death is a downstream consequence -- so the useful question is not "where did it
// crash" but "where is the main thread stuck".
//
// This periodically suspends Unity's main thread, samples RIP and the return addresses on its stack,
// and logs them as module+RVA. If the same RIP/stack repeats across samples, that's the stall site;
// if it keeps moving, the thread is live and the model is wrong. Cheap, needs no debugger, no
// registry changes, and no PageHeap (which on a process this size risks exhausting memory).
// ---------------------------------------------------------------------------------------------
//
static DWORD WINAPI HangProbeThread(LPVOID param)
{
    (void)param;
    for (;;)
    {
        Sleep(3000);

        DWORD tid = g_mainThreadId;
        if (!tid) continue;

        HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
        if (!th) continue;

        CONTEXT c;
        ZeroMemory(&c, sizeof(c));
        c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

        DWORD64 rip = 0, rsp = 0;
        uint64_t slots[12];
        int nslots = 0;
        BOOL got = FALSE;

        if (SuspendThread(th) != (DWORD)-1)
        {
            if (GetThreadContext(th, &c))
            {
                rip = c.Rip; rsp = c.Rsp; got = TRUE;
                for (int i = 0; i < 12; i++)
                {
                    uint64_t v;
                    if (!SafeReadPtr((uintptr_t)rsp + (uintptr_t)i * 8, &v)) break;
                    slots[nslots++] = v;
                }
            }
            ResumeThread(th);
        }
        CloseHandle(th);

        // Log only after resuming -- logging while the target is suspended can deadlock on the
        // logger's own lock.
        if (!got) continue;

        char s[64]; Sym((uintptr_t)rip, s, sizeof(s));
        Log("[HANG] main tid=%lu rip=%s rsp=%llX", tid, s, (unsigned long long)rsp);

        for (int i = 0; i < nslots; i++)
        {
            uintptr_t v = (uintptr_t)slots[i];
            if ((g_gaBase && v >= g_gaBase && v < g_gaEnd) ||
                (g_upBase && v >= g_upBase && v < g_upEnd) ||
                (g_rrBase && v >= g_rrBase && v < g_rrEnd))
            {
                char f[64]; Sym(v, f, sizeof(f));
                Log("[HANG]   [rsp+0x%X]=%s", i * 8, f);
            }
        }
    }
    return 0;
}

void StartHangProbe(void)
{
    ResolveModuleRanges();
    HANDLE t = CreateThread(NULL, 0, HangProbeThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    Log("[HANG] probe started (samples Unity's main thread every 3s)");
}
