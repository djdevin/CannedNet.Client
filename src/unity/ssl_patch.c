#include "common.h"
#include "ssl_patch.h"
#include "logger.h"
#include "detour.h"
#include "hwbp.h"
#include "config.h"

//
// Native TLS pinning bypass.
//
// Redirecting DNS to a self-hosted server means the TLS handshake presents a certificate the
// client's pinning will reject, so the connection dies before any HTTP is sent. The managed build
// solved this by Harmony-patching the CONCRETE BouncyCastle class
// Org.BouncyCastle.Crypto.Tls.LegacyTlsAuthentication.NotifyServerCertificate (see CLAUDE.md
// gotcha 3 -- the interface method never dispatches, you must hit the concrete impl). We do the
// same here, natively, by detouring that method's compiled il2cpp body to a no-op that returns.
//
// "NotifyServerCertificate" is an unobfuscated framework name, stable across Rec Room builds --
// this is why the managed build targeted it and why we can resolve it by literal name here.
//
// We never call the original, so the trampoline InstallDetour builds is never executed -- the
// blind 14-byte copy that would mis-handle a rip-relative prologue is therefore harmless for this
// target (we only care that the 14-byte jmp overwrite at the entry is valid, which it always is).

typedef void*       (*il2cpp_domain_get_t)(void);
typedef int         (*il2cpp_thread_attach_t)(void* domain);
typedef void**      (*il2cpp_domain_get_assemblies_t)(void* domain, size_t* size);
typedef void*       (*il2cpp_assembly_get_image_t)(void* assembly);
typedef void*       (*il2cpp_class_from_name_t)(void* image, const char* ns, const char* name);
typedef void*       (*il2cpp_class_get_method_from_name_t)(void* klass, const char* name, int argc);

static il2cpp_domain_get_t                 p_domain_get;
static il2cpp_thread_attach_t              p_thread_attach;
static il2cpp_domain_get_assemblies_t      p_domain_get_assemblies;
static il2cpp_assembly_get_image_t         p_assembly_get_image;
static il2cpp_class_from_name_t            p_class_from_name;
static il2cpp_class_get_method_from_name_t p_class_get_method_from_name;

static BYTE  backup_notify[14];
void        *original_notify = NULL;   // unused (we never call through); kept for symmetry/logging

//
// Replacement for LegacyTlsAuthentication.NotifyServerCertificate(this, cert, MethodInfo*).
// il2cpp passes args in the standard x64 convention (RCX=this, RDX=cert, R8=MethodInfo*) and the
// method returns void, so simply returning accepts every server certificate. Because the entry was
// reached via jmp (not call), our return goes straight back to the game's caller.
//
static void ReplNotifyServerCertificate(void *thisptr, void *cert, void *method)
{
    (void)thisptr; (void)cert; (void)method;
    // Accept unconditionally -- no pinning, no validation.
}

//
// Resolve a class by namespace+name across every loaded il2cpp assembly. il2cpp_class_from_name
// only searches the image it's given, so we sweep them (we don't hard-code which assembly the type
// lives in -- it's RecNet.Runtime today, but that's incidental).
//
static void* FindClass(void *domain, const char *ns, const char *name)
{
    size_t count = 0;
    void **assemblies = p_domain_get_assemblies(domain, &count);
    if (!assemblies || count == 0)
        return NULL;

    for (size_t i = 0; i < count; i++)
    {
        void *image = p_assembly_get_image(assemblies[i]);
        if (!image) continue;

        void *klass = p_class_from_name(image, ns, name);
        if (klass) return klass;
    }
    return NULL;
}

static BOOL ResolveIl2CppApi(HMODULE ga)
{
    p_domain_get                 = (il2cpp_domain_get_t)                GetProcAddress(ga, "il2cpp_domain_get");
    p_thread_attach              = (il2cpp_thread_attach_t)             GetProcAddress(ga, "il2cpp_thread_attach");
    p_domain_get_assemblies      = (il2cpp_domain_get_assemblies_t)     GetProcAddress(ga, "il2cpp_domain_get_assemblies");
    p_assembly_get_image         = (il2cpp_assembly_get_image_t)        GetProcAddress(ga, "il2cpp_assembly_get_image");
    p_class_from_name            = (il2cpp_class_from_name_t)           GetProcAddress(ga, "il2cpp_class_from_name");
    p_class_get_method_from_name = (il2cpp_class_get_method_from_name_t)GetProcAddress(ga, "il2cpp_class_get_method_from_name");

    return p_domain_get && p_domain_get_assemblies && p_assembly_get_image &&
           p_class_from_name && p_class_get_method_from_name;
}

//
// Hardcoded fallback: on the recflare-client-unstable build (Rec Room 2025-04-29) GameAssembly.dll has
// NO export table at all (stripped; confirmed RVA=0 even at runtime), so the il2cpp reflection API is
// unreachable. That build's code/metadata are decrypted in memory but the framework method addresses
// are known from the matching Cpp2IL dump (RecRoom_Info/Code/2025-04-29_02-57-34). Since this is a dead
// game with no future release, we hardcode the RVA. VA at runtime = GameAssembly_base + RVA.
// LegacyTlsAuthentication.NotifyServerCertificate(Certificate) = RVA 0x71CFD00 (vtable slot 6).
//
#define NOTIFY_SERVER_CERT_RVA 0x71CFD00

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

void PatchBestHTTPSSL(void)
{
    //
    // Wait for GameAssembly.dll to be mapped.
    //
    HMODULE ga = NULL;
    while (!ga)
    {
        ga = GetModuleHandleA("GameAssembly.dll");
        if (!ga) Sleep(100);
    }
    Log("[SSL] GameAssembly.dll at %p", ga);

    if (!ResolveIl2CppApi(ga))
    {
        //
        // No il2cpp exports (this build). Fall back to the hardcoded RVA: detour the compiled
        // NotifyServerCertificate entry directly. This is a replace-only hook (we never call the
        // original), so no il2cpp API, thread-attach, or metadata is required at all.
        //
        Log("[SSL] no il2cpp exports -- using hardcoded RVA 0x%X (build 2025-04-29)", NOTIFY_SERVER_CERT_RVA);
        BYTE *code = (BYTE *)ga + NOTIFY_SERVER_CERT_RVA;
        WaitForCode(code);
        Log("[SSL] NotifyServerCertificate code=%p prologue=%02X %02X %02X %02X",
            code, code[0], code[1], code[2], code[3]);

        //
        // Prefer a hardware breakpoint: it writes no bytes, so a native integrity check hashing
        // GameAssembly.dll's .text can't see it (see hwbp.h). This is a replace-only hook -- the
        // hook just returns, which from the breakpoint's perspective returns straight to the
        // game's caller, so no HwbpSkipOnce is needed here.
        //
        if (use_hwbp)
        {
            if (HwbpAdd(HWBP_SLOT_SSL, code, ReplNotifyServerCertificate))
            {
                Log("[SSL] TLS pinning bypassed via HWBP (no bytes patched)");
                return;
            }
            Log("[SSL] HWBP arm failed -- falling back to inline detour");
        }

        if (InstallDetour(code, ReplNotifyServerCertificate, backup_notify, NULL))
            Log("[SSL] TLS pinning bypassed via RVA (NotifyServerCertificate -> accept-all)");
        else
            Log("[SSL] failed to install NotifyServerCertificate detour (RVA path)");
        return;
    }
    Log("[SSL] il2cpp API resolved");

    //
    // Wait for the il2cpp runtime to finish init: il2cpp_domain_get() returns NULL until then.
    //
    void *domain = NULL;
    for (int i = 0; i < 600 && !domain; i++)     // up to ~60s
    {
        domain = p_domain_get();
        if (!domain) Sleep(100);
    }
    if (!domain)
    {
        Log("[SSL] il2cpp domain never came up -- aborting TLS patch");
        return;
    }

    // Our thread is native; attach it so il2cpp metadata calls are safe.
    if (p_thread_attach) p_thread_attach(domain);

    //
    // Resolve the concrete class + method. Metadata is present immediately after init, but classes
    // can briefly not resolve during early init, so retry a few times.
    //
    void *klass = NULL;
    for (int i = 0; i < 100 && !klass; i++)      // up to ~10s
    {
        klass = FindClass(domain, "Org.BouncyCastle.Crypto.Tls", "LegacyTlsAuthentication");
        if (!klass) Sleep(100);
    }
    if (!klass)
    {
        Log("[SSL] LegacyTlsAuthentication not found -- TLS pinning NOT bypassed");
        return;
    }
    Log("[SSL] LegacyTlsAuthentication klass=%p", klass);

    // argc counts only declared params: NotifyServerCertificate(Certificate) -> 1.
    void *method = p_class_get_method_from_name(klass, "NotifyServerCertificate", 1);
    if (!method)
    {
        Log("[SSL] NotifyServerCertificate(argc=1) not found -- TLS pinning NOT bypassed");
        return;
    }

    // MethodInfo.methodPointer is the first field of the struct: the compiled native entry.
    void *code = *(void **)method;
    Log("[SSL] NotifyServerCertificate MethodInfo=%p code=%p", method, code);

    if (!code)
    {
        Log("[SSL] method has no compiled body -- aborting");
        return;
    }

    // Replace-only hook: we never call the original, so pass NULL trampoline -- InstallDetour then
    // does a plain 14-byte overwrite and won't refuse a complex il2cpp prologue.
    if (InstallDetour(code, ReplNotifyServerCertificate, backup_notify, NULL))
        Log("[SSL] TLS pinning bypassed (NotifyServerCertificate -> accept-all)");
    else
        Log("[SSL] failed to install NotifyServerCertificate detour");
}
