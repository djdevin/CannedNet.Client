#include "common.h"
#include "http_rewrite.h"
#include "logger.h"
#include "config.h"
#include "strings.h"
#include "detour.h"
#include "retspoof.h"
#include "hwbp.h"
#include "crash_handler.h"

//
// HTTP-layer host rewrite.
//
// DNS-name rewrite alone can't make a request "belong" to ns.recflare.net: the client keeps the
// original URL, so TLS SNI and the Host header still say ns.rec.net. recflare serves ns.recflare.net
// (its own vhost/cert), so the request must carry that host end-to-end. We do what the managed
// SendRequestPatch did: hook the concrete, static BestHTTP.HTTPManager.SendRequest(HTTPRequest),
// read request.Uri's absolute URL, swap the host, and set a fresh Uri back before the send proceeds.
//
// This is a call-through hook (we must let the real SendRequest run), so it relies on the
// length-aware trampoline in detour.c.

typedef void*  (*il2cpp_domain_get_t)(void);
typedef int    (*il2cpp_thread_attach_t)(void*);
typedef void** (*il2cpp_domain_get_assemblies_t)(void*, size_t*);
typedef void*  (*il2cpp_assembly_get_image_t)(void*);
typedef void*  (*il2cpp_class_from_name_t)(void*, const char*, const char*);
typedef void*  (*il2cpp_class_get_method_from_name_t)(void*, const char*, int);
typedef void*  (*il2cpp_runtime_invoke_t)(void* method, void* obj, void** params, void** exc);
typedef void*  (*il2cpp_object_new_t)(void* klass);
typedef void*  (*il2cpp_string_new_t)(const char* str);
typedef uint16_t* (*il2cpp_string_chars_t)(void* str);
typedef int    (*il2cpp_string_length_t)(void* str);

static il2cpp_domain_get_t                 p_domain_get;
static il2cpp_thread_attach_t              p_thread_attach;
static il2cpp_domain_get_assemblies_t      p_domain_get_assemblies;
static il2cpp_assembly_get_image_t         p_assembly_get_image;
static il2cpp_class_from_name_t            p_class_from_name;
static il2cpp_class_get_method_from_name_t p_get_method;
static il2cpp_runtime_invoke_t             p_runtime_invoke;
static il2cpp_object_new_t                 p_object_new;
static il2cpp_string_new_t                 p_string_new;
static il2cpp_string_chars_t               p_string_chars;
static il2cpp_string_length_t              p_string_length;

// Resolved il2cpp targets.
static void *cls_Uri;
static void *m_get_Uri;          // HTTPRequest.get_Uri()  -> Uri
static void *m_set_Uri;          // HTTPRequest.set_Uri(Uri)
static void *m_get_AbsoluteUri;  // Uri.get_AbsoluteUri()  -> string
static void *m_Uri_ctor;         // Uri..ctor(string)

// Trampoline to the real SendRequest(HTTPRequest req, MethodInfo* method) -> HTTPRequest*.
typedef void* (*SendRequest_t)(void *req, void *method);
static SendRequest_t original_SendRequest;
static BYTE backup_sendrequest[32];

// HWBP call-through: the target's bytes are untouched, so "the original" is just the target address
// itself -- but calling it would re-trap, hence the one-shot skip. original_SendRequest is aimed at
// this shim when the hardware-breakpoint path is used, keeping every call site identical.
static SendRequest_t g_realSendRequest;
static void* SendRequestViaHwbp(void *req, void *method)
{
    HwbpSkipOnce(HWBP_SLOT_HTTP);
    return g_realSendRequest(req, method);
}


static void* FindClass(void *domain, const char *ns, const char *name)
{
    size_t count = 0;
    void **assemblies = p_domain_get_assemblies(domain, &count);
    for (size_t i = 0; i < count; i++)
    {
        void *image = p_assembly_get_image(assemblies[i]);
        if (!image) continue;
        void *k = p_class_from_name(image, ns, name);
        if (k) return k;
    }
    return NULL;
}

//
// Rewrite the host inside an absolute URL using the configured exact-match pairs.
// e.g. "https://ns.rec.net/api/1" -> "https://ns.recflare.net/api/1". Returns 1 if changed.
//
static int RewriteUrlHost(const char *url, char *out, size_t outlen)
{
    // Find "://"
    const char *p = strstr(url, "://");
    if (!p) return 0;
    p += 3;

    // Host runs until '/', ':', or end.
    const char *hostEnd = p;
    while (*hostEnd && *hostEnd != '/' && *hostEnd != ':') hostEnd++;

    size_t hostLen = (size_t)(hostEnd - p);
    if (hostLen == 0 || hostLen >= 256) return 0;

    char host[256];
    memcpy(host, p, hostLen);
    host[hostLen] = 0;

    char newHost[256];
    if (!RewriteHost(host, newHost, sizeof(newHost)))
        return 0;   // host not in the rewrite list

    // Reassemble: [scheme://][newHost][rest]
    size_t prefixLen = (size_t)(p - url);          // through "://"
    size_t newHostLen = strlen(newHost);
    size_t restLen = strlen(hostEnd);
    if (prefixLen + newHostLen + restLen + 1 > outlen) return 0;

    memcpy(out, url, prefixLen);
    memcpy(out + prefixLen, newHost, newHostLen);
    memcpy(out + prefixLen + newHostLen, hostEnd, restLen + 1); // include NUL
    return 1;
}

//
// Our replacement for the static SendRequest(HTTPRequest). Rewrites req.Uri then forwards.
//
static void* SendRequestHook(void *req, void *method)
{
    if (!req)
        return original_SendRequest(req, method);

    void *exc = NULL;

    // Uri uri = req.get_Uri();
    void *uri = p_runtime_invoke(m_get_Uri, req, NULL, &exc);
    if (!uri || exc)
        return original_SendRequest(req, method);

    // string url = uri.get_AbsoluteUri();
    void *urlStr = p_runtime_invoke(m_get_AbsoluteUri, uri, NULL, &exc);
    if (!urlStr || exc)
        return original_SendRequest(req, method);

    // Copy the (ASCII) URL out of the il2cpp string.
    int len = p_string_length(urlStr);
    if (len <= 0 || len >= 1024)
        return original_SendRequest(req, method);

    uint16_t *wchars = p_string_chars(urlStr);
    char url[1024];
    for (int i = 0; i < len; i++)
        url[i] = (wchars[i] < 0x80) ? (char)wchars[i] : '?';
    url[len] = 0;

    char newUrl[1100];
    if (RewriteUrlHost(url, newUrl, sizeof(newUrl)))
    {
        // Uri newUri = new Uri(newUrl); req.set_Uri(newUri);
        void *newStr = p_string_new(newUrl);
        void *newUri = p_object_new(cls_Uri);
        void *ctorArgs[1] = { newStr };
        exc = NULL;
        p_runtime_invoke(m_Uri_ctor, newUri, ctorArgs, &exc);
        if (!exc)
        {
            void *setArgs[1] = { newUri };
            exc = NULL;
            p_runtime_invoke(m_set_Uri, req, setArgs, &exc);
            if (!exc)
                Log("[HTTP] %s -> %s", url, newUrl);
            else
                Log("[HTTP] set_Uri threw, left original");
        }
        else
        {
            Log("[HTTP] new Uri(%s) threw, left original", newUrl);
        }
    }

    return original_SendRequest(req, method);
}

// ============================================================================
// Hardcoded-RVA path for the recflare-client-unstable build (Rec Room 2025-04-29).
//
// GameAssembly.dll on this build has NO export table (stripped), so the reflection API above is
// unreachable. Everything here is resolved by hardcoded address instead:
//   - il2cpp_string_new / il2cpp_object_new: found by byte-signature scan of the decrypted libil2cpp
//     (Pistol Whip 2021.3.7, metadata v29 == ours, was the reference). See memory note
//     unstable-build-identity-rvas. VA = GameAssembly_base + RVA.
//   - SendRequest(HTTPRequest): RVA from the matching Cpp2IL dump (2025-04-29).
//   - HTTPRequest.Uri is read/written as a FIELD (offset 0x168) -- no get_Uri/set_Uri needed.
//   - Uri..ctor(string) is resolved by WALKING the Uri Il2CppClass method table at runtime (struct
//     offsets from Pistol Whip il2cpp.h), since it's a framework method whose body doesn't
//     signature-scan. The Uri class comes from the live object header (*(void**)uri).
// The hook runs on the game's own il2cpp/GC thread (it's the caller of SendRequest), so no
// thread_attach is needed.
// ============================================================================
#define SENDREQUEST_RVA  0x71D7BE0
#define STRING_NEW_RVA   0x8D9EA0
#define OBJECT_NEW_RVA   0x8E1460

// HTTPRequest.Uri auto-property accessors (RecRoom methods -> RVAs from our build's dump). They ignore
// MethodInfo, so a NULL trailing arg is fine.
#define GET_URI_RVA      0x9C9460  // HTTPRequest.get_Uri() -> Uri
#define SET_URI_RVA      0x9C91D0  // HTTPRequest.set_Uri(Uri)

typedef void* (*get_uri_fn_t)(void* thisp, void* mi);
typedef void  (*set_uri_fn_t)(void* thisp, void* uri, void* mi);
static get_uri_fn_t g_get_uri;
static set_uri_fn_t g_set_uri;

#define URI_MSTRING_OFF 0x10  // System.Uri.m_String (reliable instance-field offset; reads the URL)
#define STR_LEN_OFF    0x10   // Il2CppString.length (int32)
#define STR_CHARS_OFF  0x14   // Il2CppString.chars (utf16)

// Shuffled Il2CppClass / MethodInfo offsets on this build (found empirically, see memory note):
#define CLASS_METHODS_OFF   0x60   // Il2CppClass.methods (MethodInfo** array)
#define MI_METHODPTR_OFF    0x10   // MethodInfo.methodPointer, XOR-obfuscated (== virtualMethodPointer@0x48)
#define MI_NAME_OFF         0x30   // MethodInfo.name (const char*)
#define MI_PARAMCOUNT_OFF   0x51   // MethodInfo.parameters_count (uint8)

typedef void* (*string_new_fn_t)(const char*);
typedef void* (*object_new_fn_t)(void*);
typedef void  (*uri_ctor_fn_t)(void* thisUri, void* strArg, void* methodInfo);
static string_new_fn_t g_string_new;
static object_new_fn_t g_object_new;

static int SafeReadAscii(const char *p, char *out, int n);   // fwd

// Recovered at runtime: the global XOR key that deobfuscates MethodInfo.methodPointer
// (real_VA = *(u64*)(mi+0x10) ^ key), plus the resolved Uri..ctor(string) target.
static uint64_t g_mp_key;
static void    *g_uri_ctor_entry;   // decrypted compiled entry of Uri..ctor(string)
static void    *g_uri_ctor_mi;      // its MethodInfo* (il2cpp instance methods take MethodInfo* last)
static void    *g_uri_class;        // System.Uri Il2CppClass*

// Walk a shuffled Il2CppClass' method table for `name` with parameters_count==pc (pc<0 = any); returns
// the MethodInfo*, or NULL. SEH-guarded against torn reads.
static void* FindMethod(void *klass, const char *name, int pc)
{
    void **methods;
    __try { methods = *(void ***)((BYTE *)klass + CLASS_METHODS_OFF); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
    if (!methods) return NULL;
    for (int i = 0; i < 500; i++)
    {
        void *mi;
        __try { mi = methods[i]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (!mi) break;
        const char *nm; uint8_t mc;
        __try { nm = *(const char **)((BYTE *)mi + MI_NAME_OFF); mc = *(uint8_t *)((BYTE *)mi + MI_PARAMCOUNT_OFF); }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        char s[48];
        if (!SafeReadAscii(nm, s, sizeof(s))) continue;
        if (strcmp(s, name) != 0) continue;
        if (pc >= 0 && mc != (uint8_t)pc) continue;
        return mi;
    }
    return NULL;
}

// Spin until the byte at p is decrypted code (packer decrypts .text shortly after the module maps).
static void HttpWaitForCode(const BYTE *p)
{
    for (int i = 0; i < 600; i++) { BYTE b = p[0]; if (b != 0x00 && b != 0xCC) return; Sleep(100); }
}

// SEH-safe: copy up to n-1 printable-ASCII chars from p; 1 if it looked like a C string, else 0.
static int SafeReadAscii(const char *p, char *out, int n)
{
    if (!p) return 0;
    __try {
        for (int j = 0; j < n - 1; j++) {
            char c = p[j];
            if (c == 0) { out[j] = 0; return j > 0; }
            if (c < 0x20 || c > 0x7e) return 0;
            out[j] = c;
        }
        out[n - 1] = 0; return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Read an il2cpp string's ASCII into out (SEH-safe). Returns length, or -1 on failure.
static int ReadIl2CppAscii(void *str, char *out, int cap)
{
    __try {
        if (!str) return -1;
        int len = *(int *)((BYTE *)str + STR_LEN_OFF);
        if (len < 0 || len >= cap) return -1;
        uint16_t *w = (uint16_t *)((BYTE *)str + STR_CHARS_OFF);
        for (int i = 0; i < len; i++) out[i] = (w[i] < 0x80) ? (char)w[i] : '?';
        out[len] = 0;
        return len;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

// Extract the host component from an absolute URL into host[].
static int UrlHost(const char *url, char *host, size_t cap)
{
    const char *p = strstr(url, "://");
    if (!p) return 0;
    p += 3;
    const char *e = p;
    while (*e && *e != '/' && *e != ':') e++;
    size_t hl = (size_t)(e - p);
    if (hl == 0 || hl >= cap) return 0;
    memcpy(host, p, hl); host[hl] = 0;
    return 1;
}

// Deobfuscate a MethodInfo's compiled entry. This build XOR-obfuscates MethodInfo.methodPointer with a
// global key: real_VA = *(u64*)(mi + 0x10) ^ key. We recover the key from get_Uri (whose real RVA we
// know), then apply it to any other MethodInfo. Returns the decrypted entry, or NULL.
static void* DecryptMethodPtr(void *mi)
{
    if (!g_mp_key || !mi) return NULL;
    uint64_t enc;
    __try { enc = *(uint64_t *)((BYTE *)mi + MI_METHODPTR_OFF); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
    return (void *)(uintptr_t)(enc ^ g_mp_key);
}

// One-time resolve: derive the key from get_Uri in HTTPRequest's class, then decrypt Uri..ctor(string)
// from the live Uri object's class. Returns 1 on success.
static int ResolveUriCtor(void *req, void *uri, HMODULE ga)
{
    uintptr_t base = (uintptr_t)ga;

    void *reqKlass = *(void **)req;
    void *miGetUri = FindMethod(reqKlass, "get_Uri", 0);
    if (!miGetUri) { Log("[HTTP] resolve: get_Uri MethodInfo not found"); return 0; }
    uint64_t encGetUri;
    __try { encGetUri = *(uint64_t *)((BYTE *)miGetUri + MI_METHODPTR_OFF); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    g_mp_key = encGetUri ^ (uint64_t)(base + GET_URI_RVA);
    Log("[HTTP] methodPointer key = %llX (from get_Uri)", (unsigned long long)g_mp_key);

    g_uri_class = *(void **)uri;
    void *miCtor = FindMethod(g_uri_class, ".ctor", 1);   // Uri(string) is the sole 1-param ctor
    if (!miCtor) { Log("[HTTP] resolve: Uri..ctor(string) MethodInfo not found"); return 0; }
    void *entry = DecryptMethodPtr(miCtor);
    // Sanity: entry must land inside GameAssembly's image.
    uintptr_t rva = (uintptr_t)entry - base;
    if (rva >= 0xE000000) { Log("[HTTP] resolve: Uri..ctor entry %p out of range (rva=%llX)", entry, (unsigned long long)rva); return 0; }
    g_uri_ctor_entry = entry;
    g_uri_ctor_mi    = miCtor;
    Log("[HTTP] Uri..ctor(string) entry=%p (rva=%llX) mi=%p", entry, (unsigned long long)rva, miCtor);
    return 1;
}

// SendRequest(HTTPRequest req, MethodInfo*) hook. DNS already routes ns.rec.net to recflare's IP; the
// remaining problem is TLS SNI + HTTP Host header still say ns.rec.net (Cloudflare routes by those).
// Both derive from req.Uri. So we build a fresh System.Uri from the rewritten URL and set it back --
// a real ctor parse (no cache corruption/truncation like in-place mutation). il2cpp_string_new /
// il2cpp_object_new come from the signature scan; Uri..ctor is resolved by decrypting its obfuscated
// MethodInfo.methodPointer. Runs on the game's own il2cpp/GC thread, so allocation needs no attach.
static volatile LONG g_sr_calls = 0;

static void* SendRequestHookRVA(void *req, void *method)
{
    LONG n = InterlockedIncrement(&g_sr_calls);

    // This hook runs on Unity's main thread; publish it so the hang probe knows what to sample.
    if (!g_mainThreadId) g_mainThreadId = GetCurrentThreadId();

    if (!req) return original_SendRequest(req, method);

    void *uri = (void *)SpoofCall4(g_get_uri, (uint64_t)req, 0, 0, 0);
    if (!uri) return original_SendRequest(req, method);

    char url[1024];
    if (ReadIl2CppAscii(*(void **)((BYTE *)uri + URI_MSTRING_OFF), url, sizeof(url)) < 0)
        return original_SendRequest(req, method);

    if (n <= 200) Log("[HTTP] req#%ld %s", n, url);   // DIAGNOSTIC: log every request URL

    char host[256], newHost[256], newUrl[1100];
    if (!UrlHost(url, host, sizeof(host)))            return original_SendRequest(req, method);
    if (!RewriteHost(host, newHost, sizeof(newHost))) return original_SendRequest(req, method); // not a target
    if (!RewriteUrlHost(url, newUrl, sizeof(newUrl))) return original_SendRequest(req, method);

    if (!g_uri_ctor_entry)
    {
        if (!ResolveUriCtor(req, uri, GetModuleHandleA("GameAssembly.dll")))
            return original_SendRequest(req, method);   // couldn't resolve -- leave request unchanged
    }

    __try {
        void *newStr = (void *)SpoofCall4(g_string_new, (uint64_t)newUrl, 0, 0, 0);
        void *newUri = (void *)SpoofCall4(g_object_new, (uint64_t)g_uri_class, 0, 0, 0);
        if (newStr && newUri)
        {
            // new Uri(newUrl)
            SpoofCall4(g_uri_ctor_entry, (uint64_t)newUri, (uint64_t)newStr, (uint64_t)g_uri_ctor_mi, 0);
            // req.Uri = newUri
            SpoofCall4(g_set_uri, (uint64_t)req, (uint64_t)newUri, 0, 0);
            if (n <= 60) Log("[HTTP] %s -> %s", url, newUrl);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (n <= 60) Log("[HTTP] fresh-Uri build faulted for %s -- passing through", url);
    }
    return original_SendRequest(req, method);
}

// Install the hardcoded-RVA host rewrite (call-through detour on SendRequest).
static void PatchHttpHostRewriteRVA(HMODULE ga)
{
    g_string_new = (string_new_fn_t)((BYTE *)ga + STRING_NEW_RVA);
    g_object_new = (object_new_fn_t)((BYTE *)ga + OBJECT_NEW_RVA);
    g_get_uri    = (get_uri_fn_t)((BYTE *)ga + GET_URI_RVA);
    g_set_uri    = (set_uri_fn_t)((BYTE *)ga + SET_URI_RVA);

    BYTE *code = (BYTE *)ga + SENDREQUEST_RVA;
    HttpWaitForCode(code);
    Log("[HTTP] RVA path (build 2025-04-29): SendRequest code=%p prologue=%02X %02X %02X %02X",
        code, code[0], code[1], code[2], code[3]);

    //
    // Prefer a hardware breakpoint (no bytes written -- see hwbp.h). This is a call-through hook, so
    // `original_SendRequest` is pointed at a shim that arms the one-shot pass-through and then calls
    // the real address; every existing `original_SendRequest(...)` call site keeps working unchanged.
    //
    if (use_hwbp)
    {
        g_realSendRequest = (SendRequest_t)code;
        if (HwbpAdd(HWBP_SLOT_HTTP, code, SendRequestHookRVA))
        {
            original_SendRequest = SendRequestViaHwbp;
            Log("[HTTP] host rewrite installed on SendRequest via HWBP (no bytes patched)");
            return;
        }
        Log("[HTTP] HWBP arm failed -- falling back to inline detour");
    }

    if (InstallDetour(code, SendRequestHookRVA, backup_sendrequest, (LPVOID *)&original_SendRequest))
        Log("[HTTP] host rewrite installed on SendRequest (RVA path)");
    else
        Log("[HTTP] SendRequest detour refused (RVA path) -- host rewrite NOT active");
}

static BOOL ResolveApi(HMODULE ga)
{
    p_domain_get            = (il2cpp_domain_get_t)            GetProcAddress(ga, "il2cpp_domain_get");
    p_thread_attach         = (il2cpp_thread_attach_t)         GetProcAddress(ga, "il2cpp_thread_attach");
    p_domain_get_assemblies = (il2cpp_domain_get_assemblies_t) GetProcAddress(ga, "il2cpp_domain_get_assemblies");
    p_assembly_get_image    = (il2cpp_assembly_get_image_t)    GetProcAddress(ga, "il2cpp_assembly_get_image");
    p_class_from_name       = (il2cpp_class_from_name_t)       GetProcAddress(ga, "il2cpp_class_from_name");
    p_get_method            = (il2cpp_class_get_method_from_name_t) GetProcAddress(ga, "il2cpp_class_get_method_from_name");
    p_runtime_invoke        = (il2cpp_runtime_invoke_t)        GetProcAddress(ga, "il2cpp_runtime_invoke");
    p_object_new            = (il2cpp_object_new_t)            GetProcAddress(ga, "il2cpp_object_new");
    p_string_new            = (il2cpp_string_new_t)            GetProcAddress(ga, "il2cpp_string_new");
    p_string_chars          = (il2cpp_string_chars_t)          GetProcAddress(ga, "il2cpp_string_chars");
    p_string_length         = (il2cpp_string_length_t)         GetProcAddress(ga, "il2cpp_string_length");

    return p_domain_get && p_domain_get_assemblies && p_assembly_get_image && p_class_from_name &&
           p_get_method && p_runtime_invoke && p_object_new && p_string_new && p_string_chars &&
           p_string_length;
}

void PatchHttpHostRewrite(void)
{
    if (rewrite_count == 0)
    {
        Log("[HTTP] no rewrite pairs configured -- host rewrite disabled");
        return;
    }

    HMODULE ga = NULL;
    while (!ga) { ga = GetModuleHandleA("GameAssembly.dll"); if (!ga) Sleep(100); }

    if (!ResolveApi(ga))
    {
        // No il2cpp exports (recflare-client-unstable build) -- use the hardcoded-RVA path.
        Log("[HTTP] no il2cpp exports -- using hardcoded RVA path (build 2025-04-29)");
        PatchHttpHostRewriteRVA(ga);
        return;
    }

    void *domain = NULL;
    for (int i = 0; i < 600 && !domain; i++) { domain = p_domain_get(); if (!domain) Sleep(100); }
    if (!domain) { Log("[HTTP] il2cpp domain never came up"); return; }
    if (p_thread_attach) p_thread_attach(domain);

    // Resolve classes (retry through early init).
    void *cls_Manager = NULL, *cls_Request = NULL;
    for (int i = 0; i < 100; i++)
    {
        if (!cls_Manager) cls_Manager = FindClass(domain, "BestHTTP", "HTTPManager");
        if (!cls_Request) cls_Request = FindClass(domain, "BestHTTP", "HTTPRequest");
        if (!cls_Uri)     cls_Uri     = FindClass(domain, "System",   "Uri");
        if (cls_Manager && cls_Request && cls_Uri) break;
        Sleep(100);
    }
    if (!cls_Manager || !cls_Request || !cls_Uri)
    {
        Log("[HTTP] class resolve failed (mgr=%p req=%p uri=%p)", cls_Manager, cls_Request, cls_Uri);
        return;
    }

    void *m_send        = p_get_method(cls_Manager, "SendRequest", 1);    // SendRequest(HTTPRequest)
    m_get_Uri           = p_get_method(cls_Request, "get_Uri", 0);
    m_set_Uri           = p_get_method(cls_Request, "set_Uri", 1);
    m_get_AbsoluteUri   = p_get_method(cls_Uri, "get_AbsoluteUri", 0);
    m_Uri_ctor          = p_get_method(cls_Uri, ".ctor", 1);

    if (!m_send || !m_get_Uri || !m_set_Uri || !m_get_AbsoluteUri || !m_Uri_ctor)
    {
        Log("[HTTP] method resolve failed (send=%p getUri=%p setUri=%p absUri=%p ctor=%p)",
            m_send, m_get_Uri, m_set_Uri, m_get_AbsoluteUri, m_Uri_ctor);
        return;
    }

    void *code = *(void **)m_send;   // MethodInfo.methodPointer (compiled entry)
    Log("[HTTP] SendRequest MethodInfo=%p code=%p", m_send, code);
    if (!code) { Log("[HTTP] SendRequest has no compiled body"); return; }

    if (InstallDetour(code, SendRequestHook, backup_sendrequest, (LPVOID*)&original_SendRequest))
        Log("[HTTP] host rewrite installed on SendRequest");
    else
        Log("[HTTP] SendRequest detour refused (prologue not relocatable) -- host rewrite NOT active");
}
