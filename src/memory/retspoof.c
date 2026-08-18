#include "common.h"
#include "retspoof.h"
#include "logger.h"
#include "config.h"

extern uint64_t spoof_call(void *gadget, void *target, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);

static void * volatile g_gadget;

// Same probe RVA ssl_patch.c uses to detect the packer has finished decrypting .text (build 2025-04-29,
// LegacyTlsAuthentication.NotifyServerCertificate). We don't hook it here -- just reuse it as a "is code
// decrypted yet" marker so the gadget scan doesn't run over still-encrypted bytes.
#define DECRYPT_PROBE_RVA 0x71CFD00

static void WaitForCodeDecrypt(const BYTE *p)
{
    for (int i = 0; i < 600; i++)   // ~60s cap
    {
        BOOL ok = FALSE;
        __try { ok = (p[0] != 0x00 && p[0] != 0xCC); }
        __except (EXCEPTION_EXECUTE_HANDLER) { ok = FALSE; }
        if (ok) return;
        Sleep(100);
    }
}

int InitRetSpoof(HMODULE mod)
{
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
    {
        Log("[SPOOF] GetModuleInformation failed -- return-address spoofing unavailable");
        return 0;
    }

    BYTE *base = (BYTE *)mi.lpBaseOfDll;
    SIZE_T size = mi.SizeOfImage;
    const SIZE_T PAGE = 0x1000;

    for (SIZE_T off = 0; off + 1 < size; off += PAGE)
    {
        // +1 so a match straddling a page boundary (gadget's 2nd byte in the next page) isn't missed.
        SIZE_T chunk = (off + PAGE + 1 <= size) ? (PAGE + 1) : (size - off);

        __try
        {
            for (SIZE_T i = 0; i + 1 < chunk; i++)
            {
                if (base[off + i] == 0xFF && base[off + i + 1] == 0x23)   // jmp qword ptr [rbx]
                {
                    g_gadget = base + off + i;
                    Log("[SPOOF] gadget (jmp [rbx]) found at %p (rva=0x%zX)", g_gadget, off + i);
                    return 1;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;   // unreadable page (gap between sections) -- skip it
        }
    }

    Log("[SPOOF] no jmp[rbx] gadget found in module -- return-address spoofing unavailable");
    return 0;
}

int RetSpoofReady(void)
{
    return g_gadget != NULL;
}

DWORD WINAPI PatchRetSpoof(LPVOID param)
{
    (void)param;

    HMODULE ga = NULL;
    while (!ga) { ga = GetModuleHandleA("GameAssembly.dll"); if (!ga) Sleep(100); }

    WaitForCodeDecrypt((BYTE *)ga + DECRYPT_PROBE_RVA);

    InitRetSpoof(ga);
    return 0;
}

uint64_t SpoofCall4(void *target, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    void *gadget = enable_spoof ? g_gadget : NULL;
    if (!gadget)
    {
        // No gadget resolved (yet, or scan failed) -- fall back to a direct call. Functionally
        // identical; just doesn't hide redirector.dll from a stack walk during the call.
        typedef uint64_t (*fn4_t)(uint64_t, uint64_t, uint64_t, uint64_t);
        return ((fn4_t)target)(a1, a2, a3, a4);
    }
    return spoof_call(gadget, target, a1, a2, a3, a4);
}
