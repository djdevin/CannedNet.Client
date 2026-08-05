#include "common.h"
#include "http_rewrite.h"
#include "logger.h"
#include "config.h"
#include "strings.h"
#include "detour.h"

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

    if (!ResolveApi(ga)) { Log("[HTTP] missing il2cpp exports -- aborting host rewrite"); return; }

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
