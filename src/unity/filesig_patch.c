#include "common.h"
#include "filesig_patch.h"
#include "logger.h"
#include "detour.h"
#include "config.h"

//
// Referee anti-cheat P/Invoke neutraliser -- the fix for the recurring junk-pointer crashes.
//
// How this was found (every earlier theory was wrong, so the evidence chain matters):
//   * The session ends in a hard 0xC0000005, NOT a managed quit -- hooks on both Application.Quit
//     overloads and on TerminateProcess(self) never fire.
//   * It is NOT anti-tamper reacting to our hooks: running with ZERO inline byte patches anywhere
//     (all three GameAssembly hooks on hardware breakpoints + the DNS detour off) still died at ~35s.
//   * The main thread is NOT hung -- the hang probe shows its RIP moving normally right up to death.
//   * The LAST line before the process dies is a first-chance AV: EXECUTE at 0xFFFFFFFF52520000,
//     i.e. execution transferred TO a junk pointer. It recurs on an exact 10.000s timer and is
//     survivable several times before one takes the process down.
//   * Resolved against the CORRECT dump (RecRoom_Info\Code\2025-04-29_02-57-34 -- il2cpp-tools/out is
//     a DIFFERENT build; use il2cpp-tools/whatis2025.py): the return addresses GA+0x7FAC63 /
//     0x7FACE2 / 0x7FACEE all sit below the first managed method, i.e. inside libil2cpp's own
//     P/Invoke glue, and the managed frames above them land in class `BEDNFMIFJNG` -- whose async
//     state machine carries the string:
//         "Unable to initialize Referee telemetry. Is the game protected by Referee?"
//
// So `BEDNFMIFJNG` is the Referee anti-cheat integration layer, and its `extern` methods are Referee
// native P/Invokes. Referee's native side does not exist in this build (RecRoom.exe.dll exports
// exactly one Themida-mangled symbol, `qxPzOD`), so il2cpp resolves those imports to junk and every
// call jumps into unmapped memory. The 0x52520000 / ...10 / ...20 pattern is consecutive slots of the
// same unresolved import table.
//
// Return values: 0 across the board (false / NULL / 0). That is deliberate -- the presence of the
// "Is the game protected by Referee?" message proves the client has a designed, supported path for
// "Referee is not available", so reporting failure keeps it on a code path its authors intended,
// rather than claiming success and then handing back garbage handles and uninitialised [Out] values
// that later calls would use. (Returning true for the first three was tried first: it removed the
// 0x52520000 fault and took the session from ~35s to ~60s, but left the sibling slots faulting.)
//
// All replace-only detours: calling the original is precisely what we must avoid, so no trampoline is
// needed and a complex prologue cannot be mis-decoded.
//
// FFOAJEEOIAI is included even though it hands the native side an Action<int> callback -- stubbing it
// means the callback never fires, but the status quo is a guaranteed access violation, which is
// strictly worse. If something turns out to await that callback, this is the first hook to drop.
//

// RVAs from the 2025-04-29 dump, class BEDNFMIFJNG (+ its nested DIMHKPJGDLP).
static const struct { DWORD rva; const char *name; } g_referee[] = {
    { 0x1119690, "CEGIDPKIMDF(IntPtr) -> bool"                     },
    { 0x1119710, "IAEGMFEFGPN(Guid,IntPtr,long,uint) -> IntPtr"    },
    { 0x11197D0, "ICLJICIDFJN(...) -> bool"                        },
    { 0x1119890, "JHNMFGBECCA(string,...) -> IntPtr"               },
    { 0x1119970, "KKNIDOLEIGJ(...) -> bool"                        },
    { 0x1119A50, "LJBMIMJMHIP(...) -> bool"                        },
    { 0x111A590, "FFOAJEEOIAI(Action<int>) -> void"                },
    { 0x111A5B0, "FGIGMCJGLCJ(5x[Out]) -> bool  (file sig check)"  },
    { 0x111A5E0, "GOFCGECPGIC() -> bool"                           },
    { 0x111A8C0, "LHBIHCCNGDL(IntPtr,uint) -> bool"                },
    { 0x112A1E0, "PHMMLPOMALE(int,int,IntPtr,int) -> int"          },

    //
    // NOT hooked, though it is tempting: JBMCKPKFHLD.MoveNext @0x1127670, the Referee telemetry init
    // state machine. The two remaining faults (0xFFFFFFFF52520010 / ...20) both trace back to
    // GA+0x11277D6 = MoveNext+0x166, and stubbing it DOES remove them -- but measured end to end it
    // is a net LOSS: session length dropped from ~60s to ~40s, presumably because the async task it
    // drives then never completes and something downstream waits on it. Faults that are survivable
    // beat a task that never finishes. Left alone deliberately; do not "fix" this without measuring
    // uptime again.
    //
};

#define REFEREE_COUNT ((int)(sizeof(g_referee) / sizeof(g_referee[0])))

static BYTE g_backup[REFEREE_COUNT][16];

//
// One stub serves every signature here. Static il2cpp methods take their first four args in
// RCX/RDX/R8/R9 with the rest (and MethodInfo*) on the stack, and the Win64 caller cleans the stack,
// so declaring only the register args is safe regardless of the real arity. Returning 0 in RAX is a
// valid false / NULL / 0 for every return type in the table; for the void one it is simply ignored.
//
static uint64_t ReplRefereeFail(void *a, void *b, void *c, void *d)
{
    (void)a; (void)b; (void)c; (void)d;
    return 0;
}

// Spin until the byte looks like decrypted code rather than a zero/int3 fill (the packer decrypts
// .text shortly after the module maps) -- same guard as ssl_patch.c.
static void WaitForCodeFs(const BYTE *p)
{
    for (int i = 0; i < 600; i++)
    {
        BYTE b = p[0];
        if (b != 0x00 && b != 0xCC) return;
        Sleep(100);
    }
}

//
// ---------------------------------------------------------------------------------------------
// Generic fix: repair the unresolved import slots themselves.
//
// Hooking named externs only covers the ones we can identify -- two faults remain
// (0xFFFFFFFF52520010 / ...20) whose managed caller we could not pin to a nameable extern, and there
// may be more we have never triggered. But every one of these faults jumps to an address of the form
// 0xFFFFFFFF525200xx, and that value has to be *stored* somewhere for the code to call it: il2cpp
// caches resolved P/Invoke targets in static slots inside GameAssembly.dll's data.
//
// So instead of chasing callers, scan GameAssembly's mapped image for those exact qwords and
// overwrite each with a pointer to a stub that just returns 0. That neutralises every call site --
// present and future, named and unnamed -- in one pass, and it is far more precise than a detour: the
// value is so specific (0xFFFFFFFF525200xx, "RR" poison) that a false positive is implausible.
//
// Re-scanned a few times because P/Invoke resolution is lazy: a slot may still be empty on the first
// pass and only get its junk value written once the owning method is first called.
// ---------------------------------------------------------------------------------------------
//
#define REFEREE_POISON_BASE 0xFFFFFFFF52520000ULL
#define REFEREE_POISON_MASK 0xFFFFFFFFFFFFFF00ULL   // catch ...00 through ...FF

static int PatchPoisonSlots(HMODULE ga)
{
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), ga, &mi, sizeof(mi))) return 0;

    uintptr_t base = (uintptr_t)mi.lpBaseOfDll;
    uintptr_t end  = base + mi.SizeOfImage;
    uint64_t  stub = (uint64_t)(uintptr_t)ReplRefereeFail;
    int patched = 0;

    // Walk region by region so we only touch committed, readable pages -- a 224MB image has plenty
    // of reserved-but-not-committed holes and blind reads would fault.
    uintptr_t p = base;
    while (p < end)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((void *)p, &mbi, sizeof(mbi))) break;

        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > end) regionEnd = end;

        BOOL readable = (mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) &&
                        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                        PAGE_EXECUTE_WRITECOPY));
        if (readable)
        {
            // Step ONE byte, not eight. The first slot found this way (GA+0x7FACD8, holding
            // ...52520020) happened to be 8-aligned, but these values also appear as 64-bit
            // immediates embedded in instructions (`mov rax, imm64` / `call rax`), which are almost
            // never aligned -- an aligned-only scan silently misses them. Patching an immediate is
            // just as valid as patching a data slot: the instruction then loads our stub instead.
            for (uintptr_t a = (uintptr_t)mbi.BaseAddress; a + 8 <= regionEnd; a += 1)
            {
                uint64_t v = *(volatile uint64_t *)a;
                if ((v & REFEREE_POISON_MASK) != REFEREE_POISON_BASE) continue;

                DWORD old;
                if (VirtualProtect((void *)a, 8, PAGE_READWRITE, &old))
                {
                    *(volatile uint64_t *)a = stub;
                    VirtualProtect((void *)a, 8, old, &old);
                    patched++;
                    Log("[REFEREE] repaired import slot at GA+0x%llX (was %llX -> safe stub)",
                        (unsigned long long)(a - base), (unsigned long long)v);
                }
            }
        }

        p = regionEnd > p ? regionEnd : p + 0x1000;
    }
    return patched;
}

void PatchFileSigCheck(void)
{
    HMODULE ga = NULL;
    while (!ga) { ga = GetModuleHandleA("GameAssembly.dll"); if (!ga) Sleep(100); }

    int ok = 0;
    for (int i = 0; i < REFEREE_COUNT; i++)
    {
        BYTE *code = (BYTE *)ga + g_referee[i].rva;
        WaitForCodeFs(code);

        if (InstallDetour(code, ReplRefereeFail, g_backup[i], NULL))
        {
            ok++;
            Log("[REFEREE] neutralised GA+0x%X %s", g_referee[i].rva, g_referee[i].name);
        }
        else
        {
            Log("[REFEREE] FAILED to hook GA+0x%X %s (prologue %02X %02X %02X %02X)",
                g_referee[i].rva, g_referee[i].name, code[0], code[1], code[2], code[3]);
        }
    }

    Log("[REFEREE] %d/%d Referee P/Invokes neutralised (all return 0 = 'Referee unavailable')",
        ok, REFEREE_COUNT);

    // Sweep the unresolved import slots too. Lazy resolution means a slot can be written long after
    // startup, so repeat for a while rather than scanning once.
    int total = 0;
    for (int pass = 0; pass < 10; pass++)
    {
        DWORD t0 = GetTickCount();
        int n = PatchPoisonSlots(ga);
        total += n;
        if (n || pass == 0)
            Log("[REFEREE] pass %d: repaired %d poisoned import slot(s) (scan %lu ms)",
                pass, n, GetTickCount() - t0);
        Sleep(3000);
    }
    Log("[REFEREE] import-slot sweep finished, %d slot(s) repaired in total", total);
}
