#include "common.h"
#include "antitamper_patch.h"
#include "logger.h"
#include "detour.h"

//
// Anti-tamper report funnel suppression (recflare-client-unstable, build 2025-04-29).
//
// The client funnels EVERY tamper detection through one static method:
//     DKABIBJEBOC BBFGNPPNKOG(GDMJABNKMGN kind, string detail, int? code, bool flag)   [RVA 0x774F610]
// (the equivalent of the managed patcher's AAKMENFOFEI.GIOHEBODOAC anti-tamper funnel). It creates a
// "Hile" warning -> POST api/PlayerReporting/v1/hile -> and warnings flagged shouldAlwaysQuit force the
// app to quit. On this setup two things trip it: our own inline hooks (Inject/UnknownDll/
// Memory_Hash_Mismatch) and, most visibly, ImageSignature (kind=6) -- recflare stamps CDN image URLs
// with a placeholder `sig=p1` the client's signature check rejects. Result: ~30s in, the client reports
// the ImageSignature failure and locks up / exits.
//
// The violation taxonomy (enum names survive obfuscation): Obscured=0 Time=1 Inject=2 GiftCount=3
// Engine=4 UnknownDll=5 ImageSignature=6 AvatarHack=7 NetworkCertificate*=100.. Memory_Hash_Mismatch=500
// Native_Memory_Hash_Mismatch=700.
//
// We detour the funnel replace-only and return null (a report is fire-and-forget; the callers don't
// await the result), so no warning is created, nothing is POSTed, and nothing quits. Static il2cpp
// method ABI: args in RCX/RDX/R8/R9 (kind, detail, code, flag), MethodInfo* on the stack; caller cleans
// up, so a null-returning replacement is safe.
//

#define ANTITAMPER_FUNNEL_RVA  0x774F610

typedef void* (*funnel_fn_t)(void *kind, void *detail, void *code, void *flag);
static BYTE backup_funnel[32];

// Log the first few suppressed reports so a launch reveals which detections fired. kind arrives as the
// enum's integer value in RCX; detail is an il2cpp string in RDX (length@0x10, chars@0x14).
static void LogSuppressed(void *kind, void *detail)
{
    // Log each DISTINCT kind once (so memory-hash detections kind=500/700 surface even amid a flood of
    // ImageSignature=6 reports), plus the first dozen overall.
    static volatile LONG n = 0;
    static LONG seenKinds[64]; static volatile LONG seenCount = 0;
    unsigned long long kv = (unsigned long long)(uintptr_t)kind;
    int known = 0;
    for (LONG s = 0; s < seenCount && s < 64; s++) if (seenKinds[s] == (LONG)kv) { known = 1; break; }
    LONG i = InterlockedIncrement(&n);
    if (known && i > 12) return;
    if (!known) { LONG idx = InterlockedIncrement(&seenCount) - 1; if (idx < 64) seenKinds[idx] = (LONG)kv; }
    char msg[256] = "";
    __try {
        if (detail) {
            int len = *(int *)((BYTE *)detail + 0x10);
            if (len > 0 && len < (int)sizeof(msg)) {
                uint16_t *w = (uint16_t *)((BYTE *)detail + 0x14);
                for (int j = 0; j < len; j++) msg[j] = (w[j] < 0x80) ? (char)w[j] : '?';
                msg[len] = 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { msg[0] = 0; }
    Log("[ANTITAMPER] suppressed report kind=%llu detail=\"%s\"",
        (unsigned long long)(uintptr_t)kind, msg);
}

static void* FunnelHook(void *kind, void *detail, void *code, void *flag)
{
    (void)code; (void)flag;
    LogSuppressed(kind, detail);
    return NULL;   // no warning, no /hile POST, no quit
}

void PatchAntiTamper(void)
{
    HMODULE ga = NULL;
    while (!ga) { ga = GetModuleHandleA("GameAssembly.dll"); if (!ga) Sleep(100); }

    BYTE *code = (BYTE *)ga + ANTITAMPER_FUNNEL_RVA;
    for (int i = 0; i < 600; i++) { if (code[0] != 0x00 && code[0] != 0xCC) break; Sleep(100); }
    Log("[ANTITAMPER] funnel code=%p prologue=%02X %02X %02X %02X",
        code, code[0], code[1], code[2], code[3]);

    // Replace-only: we never call the original, so a blind 14-byte overwrite is safe.
    if (InstallDetour(code, FunnelHook, backup_funnel, NULL))
        Log("[ANTITAMPER] tamper-report funnel neutralized (returns null)");
    else
        Log("[ANTITAMPER] funnel detour refused -- anti-tamper NOT suppressed");
}
