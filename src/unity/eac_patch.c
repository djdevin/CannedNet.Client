#include "common.h"
#include "eac_patch.h"
#include "logger.h"
#include "detour.h"

//
// Native port of the managed EACPatches (RecNetPlugin). Two hooks on RecRoom.AntiCheat.EACManager:
//
//   1. Readiness check -> true. The client won't proceed unless EAC reports "ready"; the real check
//      depends on the EasyAntiCheat runtime talking to live services that no longer exist. It's the
//      only static, 0-param, bool-returning, non-property-getter method on EACManager (obfuscated
//      name rotates every build -- resolved by that signature).
//
//   2. GenerateChallengeResponse(string) -> base64(challenge). Unobfuscated name. The server-side
//      handshake expects base64 of the challenge (empty/null -> base64("nothing")), matching what the
//      managed build supplied.
//
// Both are replace-only detours (we never call the originals). Safe to modify EACManager code now that
// the native memory-integrity scan is neutralized (see memcheck_patch.c) -- otherwise this would trip
// the hash mismatch.

#define METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK 0x0007
#define METHOD_ATTRIBUTE_STATIC             0x0010
#define METHOD_ATTRIBUTE_SPECIAL_NAME       0x0800
#define IL2CPP_TYPE_BOOLEAN                 0x02

typedef void*    (*il2cpp_domain_get_t)(void);
typedef int      (*il2cpp_thread_attach_t)(void*);
typedef void**   (*il2cpp_domain_get_assemblies_t)(void*, size_t*);
typedef void*    (*il2cpp_assembly_get_image_t)(void*);
typedef void*    (*il2cpp_class_from_name_t)(void*, const char*, const char*);
typedef void*    (*il2cpp_class_get_method_from_name_t)(void*, const char*, int);
typedef void*    (*il2cpp_class_get_methods_t)(void*, void**);
typedef const char* (*il2cpp_method_get_name_t)(void*);
typedef uint32_t (*il2cpp_method_get_flags_t)(void*, uint32_t*);
typedef uint32_t (*il2cpp_method_get_param_count_t)(void*);
typedef void*    (*il2cpp_method_get_return_type_t)(void*);
typedef int      (*il2cpp_type_get_type_t)(void*);
typedef void*    (*il2cpp_string_new_t)(const char*);
typedef uint16_t*(*il2cpp_string_chars_t)(void*);
typedef int      (*il2cpp_string_length_t)(void*);

static il2cpp_domain_get_t              p_domain_get;
static il2cpp_thread_attach_t           p_thread_attach;
static il2cpp_domain_get_assemblies_t   p_get_assemblies;
static il2cpp_assembly_get_image_t      p_get_image;
static il2cpp_class_from_name_t         p_class_from_name;
static il2cpp_class_get_method_from_name_t p_get_method;
static il2cpp_class_get_methods_t       p_get_methods;
static il2cpp_method_get_name_t         p_method_name;
static il2cpp_method_get_flags_t        p_method_flags;
static il2cpp_method_get_param_count_t  p_param_count;
static il2cpp_method_get_return_type_t  p_return_type;
static il2cpp_type_get_type_t           p_type_kind;
static il2cpp_string_new_t              p_string_new;
static il2cpp_string_chars_t            p_string_chars;
static il2cpp_string_length_t           p_string_length;

static int  g_gcr_static;                 // is GenerateChallengeResponse a static method?
static BYTE backup_isready[32];
static BYTE backup_gcr[32];


// ---- base64 of a UTF-8 buffer ----
static void base64(const unsigned char *in, size_t len, char *out)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3)
    {
        unsigned v = in[i] << 16;
        int n = 1;
        if (i + 1 < len) { v |= in[i + 1] << 8; n = 2; }
        if (i + 2 < len) { v |= in[i + 2];      n = 3; }
        out[o++] = tbl[(v >> 18) & 0x3F];
        out[o++] = tbl[(v >> 12) & 0x3F];
        out[o++] = (n >= 2) ? tbl[(v >> 6) & 0x3F] : '=';
        out[o++] = (n >= 3) ? tbl[v & 0x3F]        : '=';
    }
    out[o] = 0;
}

// UTF-16 (il2cpp string) -> UTF-8. Returns byte count written (excl NUL). BMP only; ample buffer assumed.
static size_t utf16_to_utf8(const uint16_t *w, int wlen, unsigned char *out, size_t outcap)
{
    size_t o = 0;
    for (int i = 0; i < wlen && o + 4 < outcap; i++)
    {
        uint32_t c = w[i];
        if (c < 0x80) out[o++] = (unsigned char)c;
        else if (c < 0x800)
        {
            out[o++] = (unsigned char)(0xC0 | (c >> 6));
            out[o++] = (unsigned char)(0x80 | (c & 0x3F));
        }
        else
        {
            out[o++] = (unsigned char)(0xE0 | (c >> 12));
            out[o++] = (unsigned char)(0x80 | ((c >> 6) & 0x3F));
            out[o++] = (unsigned char)(0x80 | (c & 0x3F));
        }
    }
    out[o] = 0;
    return o;
}


// ---- hooks ----

// Readiness check: force true. Static 0-param bool -> native (RCX=MethodInfo*); return in AL.
static int32_t IsReadyHook(void *methodInfo)
{
    (void)methodInfo;
    return 1;
}

// GenerateChallengeResponse(string) -> base64(challenge). Register order is RCX,RDX,R8 regardless of
// static-ness; for an instance method a=this,b=challenge,c=MethodInfo, for static a=challenge,b=MethodInfo.
static void* GcrHook(void *a, void *b, void *c)
{
    (void)c;
    void *challenge = g_gcr_static ? a : b;

    unsigned char utf8[1024];
    const char *src;

    if (challenge)
    {
        int len = p_string_length(challenge);
        if (len > 0 && len < 300)
        {
            uint16_t *w = p_string_chars(challenge);
            utf16_to_utf8(w, len, utf8, sizeof(utf8));
            src = (const char *)utf8;
        }
        else src = "nothing";
    }
    else src = "nothing";

    char b64[1600];
    base64((const unsigned char *)src, strlen(src), b64);
    return p_string_new(b64);
}


static BOOL ResolveApi(HMODULE ga)
{
    p_domain_get     = (il2cpp_domain_get_t)             GetProcAddress(ga, "il2cpp_domain_get");
    p_thread_attach  = (il2cpp_thread_attach_t)          GetProcAddress(ga, "il2cpp_thread_attach");
    p_get_assemblies = (il2cpp_domain_get_assemblies_t)  GetProcAddress(ga, "il2cpp_domain_get_assemblies");
    p_get_image      = (il2cpp_assembly_get_image_t)     GetProcAddress(ga, "il2cpp_assembly_get_image");
    p_class_from_name= (il2cpp_class_from_name_t)        GetProcAddress(ga, "il2cpp_class_from_name");
    p_get_method     = (il2cpp_class_get_method_from_name_t) GetProcAddress(ga, "il2cpp_class_get_method_from_name");
    p_get_methods    = (il2cpp_class_get_methods_t)      GetProcAddress(ga, "il2cpp_class_get_methods");
    p_method_name    = (il2cpp_method_get_name_t)        GetProcAddress(ga, "il2cpp_method_get_name");
    p_method_flags   = (il2cpp_method_get_flags_t)       GetProcAddress(ga, "il2cpp_method_get_flags");
    p_param_count    = (il2cpp_method_get_param_count_t) GetProcAddress(ga, "il2cpp_method_get_param_count");
    p_return_type    = (il2cpp_method_get_return_type_t) GetProcAddress(ga, "il2cpp_method_get_return_type");
    p_type_kind      = (il2cpp_type_get_type_t)          GetProcAddress(ga, "il2cpp_type_get_type");
    p_string_new     = (il2cpp_string_new_t)             GetProcAddress(ga, "il2cpp_string_new");
    p_string_chars   = (il2cpp_string_chars_t)           GetProcAddress(ga, "il2cpp_string_chars");
    p_string_length  = (il2cpp_string_length_t)          GetProcAddress(ga, "il2cpp_string_length");

    return p_domain_get && p_get_assemblies && p_get_image && p_class_from_name && p_get_method &&
           p_get_methods && p_method_name && p_method_flags && p_param_count && p_return_type &&
           p_type_kind && p_string_new && p_string_chars && p_string_length;
}

static void* FindClass(void *domain, const char *ns, const char *name)
{
    size_t n = 0;
    void **asms = p_get_assemblies(domain, &n);
    for (size_t i = 0; i < n; i++)
    {
        void *img = p_get_image(asms[i]);
        if (!img) continue;
        void *k = p_class_from_name(img, ns, name);
        if (k) return k;
    }
    return NULL;
}

void PatchEAC(void)
{
    HMODULE ga = NULL;
    while (!ga) { ga = GetModuleHandleA("GameAssembly.dll"); if (!ga) Sleep(100); }

    if (!ResolveApi(ga)) { Log("[EAC] missing il2cpp exports -- aborting"); return; }

    void *domain = NULL;
    for (int i = 0; i < 600 && !domain; i++) { domain = p_domain_get(); if (!domain) Sleep(100); }
    if (!domain) { Log("[EAC] il2cpp domain never came up"); return; }
    if (p_thread_attach) p_thread_attach(domain);

    void *cls = NULL;
    for (int i = 0; i < 100 && !cls; i++) { cls = FindClass(domain, "RecRoom.AntiCheat", "EACManager"); if (!cls) Sleep(100); }
    if (!cls) { Log("[EAC] RecRoom.AntiCheat.EACManager not found"); return; }

    //
    // Readiness check: the sole static, 0-param, bool, non-property-getter method.
    //
    void *isReady = NULL;
    int readyCandidates = 0;
    void *iter = NULL, *m;
    while ((m = p_get_methods(cls, &iter)) != NULL)
    {
        uint32_t iflags = 0;
        uint32_t f = p_method_flags(m, &iflags);
        if (!(f & METHOD_ATTRIBUTE_STATIC)) continue;
        if (f & METHOD_ATTRIBUTE_SPECIAL_NAME) continue;   // exclude property getters
        if (p_param_count(m) != 0) continue;
        void *rt = p_return_type(m);
        if (!rt || p_type_kind(rt) != IL2CPP_TYPE_BOOLEAN) continue;

        const char *mn = p_method_name(m);
        Log("[EAC] readiness candidate: %s", mn ? mn : "?");
        isReady = m;
        readyCandidates++;
    }

    if (!isReady)
        Log("[EAC] no static bool() readiness method -- readiness NOT forced");
    else
    {
        if (readyCandidates > 1)
            Log("[EAC] WARNING %d readiness candidates; using the last", readyCandidates);
        void *code = *(void **)isReady;
        if (code && InstallDetour(code, IsReadyHook, backup_isready, NULL))
            Log("[EAC] readiness check forced true");
        else
            Log("[EAC] failed to hook readiness check");
    }

    //
    // GenerateChallengeResponse(string) -> base64(challenge).
    //
    void *gcr = p_get_method(cls, "GenerateChallengeResponse", 1);
    if (!gcr)
        Log("[EAC] GenerateChallengeResponse(argc=1) not found -- challenge NOT patched");
    else
    {
        uint32_t iflags = 0;
        uint32_t f = p_method_flags(gcr, &iflags);
        g_gcr_static = (f & METHOD_ATTRIBUTE_STATIC) != 0;
        void *code = *(void **)gcr;
        if (code && InstallDetour(code, GcrHook, backup_gcr, NULL))
            Log("[EAC] GenerateChallengeResponse -> base64(challenge) (static=%d)", g_gcr_static);
        else
            Log("[EAC] failed to hook GenerateChallengeResponse");
    }
}
