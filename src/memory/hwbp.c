#include "common.h"
#include "hwbp.h"
#include "logger.h"
#include <tlhelp32.h>

//
// See include/hwbp.h for why this exists. Mechanics:
//
// An execute breakpoint in DR0-3 makes the CPU raise #DB *before* the instruction at that address
// runs; Windows delivers it as EXCEPTION_SINGLE_STEP to vectored handlers. Our handler rewrites
// CONTEXT.Rip to the hook and resumes -- so the hook is entered with RCX/RDX/R8/R9 and the return
// address exactly as the real function would have seen them, and a plain `return` from the hook
// goes straight back to the game's caller. No bytes are touched anywhere.
//
// Calling the original from a hook needs care: the call re-enters the same address and would trap
// again forever. HwbpSkipOnce arms a thread-local flag; the handler consumes it and resumes with
// EFlags.RF (resume flag) set, which suppresses the instruction breakpoint for exactly one
// instruction. RF is essential -- without it, resuming at an un-executed faulting address just
// re-faults immediately.
//

static void *g_target[HWBP_MAX];
static void *g_hook[HWBP_MAX];
static int   g_active;                       // bitmask of armed slots
static void *g_veh;
static CRITICAL_SECTION g_lock;
static BOOL  g_ready;

// One-shot pass-through, per thread per slot (see HwbpSkipOnce).
static __declspec(thread) int t_skip[HWBP_MAX];

// DR7 layout: bit (2*i) = local enable for slot i. The 4 bits at (16 + 4*i) are that slot's
// condition (bits 0-1) and length (bits 2-3); 0b0000 = break on execute, length 1 -- the only
// combination valid for an execute breakpoint.
static DWORD64 BuildDr7(int mask)
{
    DWORD64 dr7 = 0;
    for (int i = 0; i < HWBP_MAX; i++)
        if (mask & (1 << i))
            dr7 |= (DWORD64)1 << (i * 2);        // Ln enable; RW/LEN nibble stays 0 = execute
    return dr7;
}

// Push the current register set into one thread. The thread must not be us.
static BOOL ApplyToThread(HANDLE th)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (SuspendThread(th) == (DWORD)-1) return FALSE;

    BOOL ok = FALSE;
    if (GetThreadContext(th, &ctx))
    {
        ctx.Dr0 = (DWORD64)(uintptr_t)g_target[0];
        ctx.Dr1 = (DWORD64)(uintptr_t)g_target[1];
        ctx.Dr2 = (DWORD64)(uintptr_t)g_target[2];
        ctx.Dr3 = (DWORD64)(uintptr_t)g_target[3];
        ctx.Dr6 = 0;
        ctx.Dr7 = BuildDr7(g_active);
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        ok = SetThreadContext(th, &ctx);
    }

    ResumeThread(th);
    return ok;
}

//
// Apply to every thread in this process except ourselves. `seen` is a caller-owned list of TIDs we
// have already programmed, so the watcher only pays for genuinely new threads.
//
// Deliberately does no logging while a thread is suspended: the logger takes a lock, and suspending
// the thread that happens to hold it and then trying to log would deadlock the process.
//
static int ApplyToAllThreads(DWORD *seen, int *seenCount, int seenMax)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId(), self = GetCurrentThreadId();
    int applied = 0;

    if (Thread32First(snap, &te))
    {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == self)      continue;

            int known = 0;
            for (int i = 0; i < *seenCount; i++)
                if (seen[i] == te.th32ThreadID) { known = 1; break; }
            if (known) continue;

            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                   FALSE, te.th32ThreadID);
            if (th)
            {
                if (ApplyToThread(th)) applied++;
                CloseHandle(th);
                if (*seenCount < seenMax) seen[(*seenCount)++] = te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return applied;
}

// Diagnostics: did the CPU ever deliver a #DB to us at all? If this stays 0 while the debug
// registers read back as armed, the registers are being faked (the protector hooking
// NtGet/SetContextThread) and hardware breakpoints cannot work in this process.
static volatile LONG g_singleStepSeen;
static volatile LONG g_vehCalls;

static LONG CALLBACK HwbpVeh(EXCEPTION_POINTERS *ep)
{
    InterlockedIncrement(&g_vehCalls);

    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&g_singleStepSeen);

    PCONTEXT ctx = ep->ContextRecord;
    DWORD64  dr6 = ctx->Dr6;

    for (int i = 0; i < HWBP_MAX; i++)
    {
        if (!(dr6 & ((DWORD64)1 << i))) continue;   // not this slot
        if (!(g_active & (1 << i)))     continue;   // not ours

        ctx->Dr6 = 0;                               // ack the hit

        if (t_skip[i])
        {
            // Deliberate pass-through from a call-through hook: run the real instruction once.
            t_skip[i] = 0;
            ctx->EFlags |= 0x10000;                 // RF -- suppress this breakpoint for 1 insn
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Enter the hook with the callee's exact register state.
        ctx->Rip = (DWORD64)(uintptr_t)g_hook[i];
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Re-apply to newly created threads. BestHTTP and Unity both spawn threads well after our hooks go
// in, and a thread born without the debug registers set would sail straight through the target.
//
// Read DR7/DR0 back out of some thread that is not us, so we can tell whether our registers are
// actually sticking. Themida-class protectors routinely zero the debug registers to kill hardware
// breakpoints, and that failure is otherwise silent -- the hook simply never fires.
//
static void CheckPersistence(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId(), self = GetCurrentThreadId();
    // Survey EVERY thread rather than sampling one -- if the protector only scrubs the threads that
    // actually run game code, a single sample can look perfectly healthy while the threads we care
    // about are disarmed.
    int total = 0, armed = 0, cleared = 0, unreadable = 0;

    if (Thread32First(snap, &te))
    {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
            total++;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) { unreadable++; continue; }
            CONTEXT c; ZeroMemory(&c, sizeof(c)); c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (SuspendThread(th) != (DWORD)-1)
            {
                if (GetThreadContext(th, &c))
                {
                    if (c.Dr0 == (DWORD64)(uintptr_t)g_target[0] && g_target[0]) armed++;
                    else cleared++;
                }
                else unreadable++;
                ResumeThread(th);
            }
            else unreadable++;
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    // Log outside the suspend window (logging while a thread is suspended can deadlock on the
    // logger lock).
    Log("[HWBP] survey: %d threads -- Dr0 armed=%d cleared=%d unreadable=%d | vehCalls=%ld singleStep=%ld",
        total, armed, cleared, unreadable, (long)g_vehCalls, (long)g_singleStepSeen);
}

//
// ---------------------------------------------------------------------------------------------
// Self-test: prove whether hardware breakpoints work AT ALL in this process.
//
// Everything we hook lives in code the protector cares about, so "the hook didn't fire" is
// ambiguous -- it could be the target, the thread, or the registers being faked. This arms the spare
// slot on a function inside OUR OWN DLL and calls it from a fresh thread. That target is code no
// integrity check is watching, so:
//   fires     -> the engine is sound; the failure is specific to the GameAssembly targets/threads.
//   no fire   -> debug registers are non-functional process-wide (faked Get/SetContextThread), and
//                hardware breakpoints are a dead end on this build. Definitive.
// ---------------------------------------------------------------------------------------------
//
#define HWBP_SLOT_SELFTEST 3

static volatile LONG g_selfTestSideEffect;
static volatile LONG g_selfTestHookRan;

__declspec(noinline) static void HwbpSelfTestTarget(void)
{
    // Volatile side effect so the optimiser can neither inline nor elide this function.
    InterlockedIncrement(&g_selfTestSideEffect);
}

static void HwbpSelfTestHook(void)
{
    g_selfTestHookRan = 1;
    // Replace-only: returning here goes straight back to HwbpSelfTestTarget's caller.
}

static DWORD WINAPI HwbpSelfTestThread(LPVOID param)
{
    (void)param;
    // Give the applier a couple of passes to program this newly created thread.
    Sleep(1200);

    LONG before = g_selfTestSideEffect;
    HwbpSelfTestTarget();

    //
    // Disarm immediately. Leaving the self-test slot armed keeps the watcher suspending and
    // resuming every thread in the process (~135 of them) five times a second forever, which is
    // pure overhead once the question is answered -- and poking every thread's context that often
    // inside a protected process is exactly the kind of thing worth NOT doing while hunting a crash.
    //
    HwbpDisarm(HWBP_SLOT_SELFTEST);

    if (g_selfTestHookRan)
        Log("[HWBP] SELF-TEST PASSED -- breakpoint fired on our own function; the engine works "
            "(hooks disarmed again)");
    else
        Log("[HWBP] SELF-TEST FAILED -- armed our own function and it did NOT trap (side effect ran: "
            "%ld->%ld, vehCalls=%ld singleStep=%ld). Debug registers are non-functional in this "
            "process; hardware breakpoints are a DEAD END here.",
            (long)before, (long)g_selfTestSideEffect, (long)g_vehCalls, (long)g_singleStepSeen);
    return 0;
}

void HwbpSelfTest(void)
{
    if (!HwbpAdd(HWBP_SLOT_SELFTEST, (void *)HwbpSelfTestTarget, (void *)HwbpSelfTestHook))
    {
        Log("[HWBP] self-test could not arm its slot");
        return;
    }
    HANDLE t = CreateThread(NULL, 0, HwbpSelfTestThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

static DWORD WINAPI HwbpWatcher(LPVOID param)
{
    (void)param;
    static DWORD seen[512];
    int pass = 0;

    for (;;)
    {
        if (g_active)
        {
            //
            // Re-arm EVERY thread on EVERY pass, not just threads we haven't seen. The protector
            // inside RecRoom.exe.dll zeroes DR0-DR3 a few seconds in (observed: Dr0 goes
            // 7FFC54B6FD00 -> 0 while Dr7 stays 0x415), which is a standard anti-debug move. A
            // one-shot arm is therefore silently disarmed long before the hooked functions are ever
            // called, so persistence is the whole game here -- hence the deliberately throwaway
            // seen-list.
            //
            int seenCount = 0;
            EnterCriticalSection(&g_lock);
            ApplyToAllThreads(seen, &seenCount, (int)(sizeof(seen) / sizeof(seen[0])));
            LeaveCriticalSection(&g_lock);

            // Report the first few passes, then occasionally -- enough to see whether the registers
            // survive without spamming the log.
            if (pass < 3 || (pass % 25) == 0) CheckPersistence();
            pass++;
        }
        Sleep(200);
    }
    return 0;
}

BOOL HwbpInit(void)
{
    if (g_ready) return TRUE;

    InitializeCriticalSection(&g_lock);

    // First in the chain: this must see #DB before anything else decides to swallow it.
    g_veh = AddVectoredExceptionHandler(1, HwbpVeh);
    if (!g_veh) { Log("[HWBP] AddVectoredExceptionHandler failed (%lu)", GetLastError()); return FALSE; }

    HANDLE w = CreateThread(NULL, 0, HwbpWatcher, NULL, 0, NULL);
    if (w) CloseHandle(w);

    g_ready = TRUE;
    Log("[HWBP] engine ready (VEH installed, per-thread watcher running)");
    return TRUE;
}

BOOL HwbpAdd(int slot, void *target, void *hook)
{
    if (slot < 0 || slot >= HWBP_MAX || !target || !hook) return FALSE;
    if (!HwbpInit()) return FALSE;

    EnterCriticalSection(&g_lock);
    g_target[slot] = target;
    g_hook[slot]   = hook;
    g_active      |= (1 << slot);

    // Program every existing thread now; the watcher covers ones created later. Pass a throwaway
    // seen-list so this call reprograms all current threads with the new register set.
    DWORD seen[512]; int n = 0;
    int applied = ApplyToAllThreads(seen, &n, (int)(sizeof(seen) / sizeof(seen[0])));
    LeaveCriticalSection(&g_lock);

    Log("[HWBP] slot %d armed: target=%p hook=%p (applied to %d existing threads)",
        slot, target, hook, applied);
    return TRUE;
}

void HwbpSkipOnce(int slot)
{
    if (slot >= 0 && slot < HWBP_MAX) t_skip[slot] = 1;
}

void HwbpDisarm(int slot)
{
    if (slot < 0 || slot >= HWBP_MAX) return;

    EnterCriticalSection(&g_lock);
    g_target[slot] = NULL;
    g_hook[slot]   = NULL;
    g_active      &= ~(1 << slot);

    // Push the cleared register set out to every thread. With g_active back to 0 the watcher then
    // idles instead of suspending the whole process on a loop.
    DWORD seen[512]; int n = 0;
    ApplyToAllThreads(seen, &n, (int)(sizeof(seen) / sizeof(seen[0])));
    LeaveCriticalSection(&g_lock);
}
