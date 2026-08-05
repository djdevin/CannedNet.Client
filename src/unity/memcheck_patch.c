#include "common.h"
#include "memcheck_patch.h"
#include "logger.h"
#include "detour.h"

//
// Native port of the managed MemoryIntegrityPatch (see the RecNetPlugin project). The client runs a
// background native memory-integrity scan that hashes GameAssembly.dll code and compares against
// baked-in hashes; our inline hooks change that memory, so the scan mismatches and boot dies with
// "Launch validation failed. Is Rec Room installed correctly?". The scanner is identified NOT by its
// obfuscated name (which rotates every build) but by its signature: a class holding both a
// System.Threading.Thread and a System.Threading.CancellationTokenSource field (the background
// scanner + its cancellation source). Its public, instance, parameterless, non-void method is the
// scan-start entry point; the type it returns is the promise the boot step awaits. We detour that
// entry (replace-only -- we never call the original) to instead return an already-resolved promise,
// obtained from the promise type's static parameterless "Resolved" property getter. Boot then sees
// an instantly-satisfied promise and proceeds.
//
// Everything here is resolved through the il2cpp reflection API at runtime; there are no hardcoded
// obfuscated names. The first run logs generously so an ambiguous match can be diagnosed.

// --- il2cpp method attribute flags / type enum (stable il2cpp-api constants) ---
#define METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK 0x0007
#define METHOD_ATTRIBUTE_PUBLIC             0x0006
#define METHOD_ATTRIBUTE_STATIC             0x0010
#define METHOD_ATTRIBUTE_SPECIAL_NAME       0x0800
#define IL2CPP_TYPE_VOID                    0x01

typedef void*    (*il2cpp_domain_get_t)(void);
typedef int      (*il2cpp_thread_attach_t)(void*);
typedef void**   (*il2cpp_domain_get_assemblies_t)(void*, size_t*);
typedef void*    (*il2cpp_assembly_get_image_t)(void*);
typedef const char* (*il2cpp_image_get_name_t)(void*);
typedef size_t   (*il2cpp_image_get_class_count_t)(void*);
typedef void*    (*il2cpp_image_get_class_t)(void*, size_t);
typedef const char* (*il2cpp_class_get_name_t)(void*);
typedef void*    (*il2cpp_class_get_fields_t)(void*, void**);
typedef void*    (*il2cpp_field_get_type_t)(void*);
typedef char*    (*il2cpp_type_get_name_t)(void*);
typedef void*    (*il2cpp_class_get_methods_t)(void*, void**);
typedef const char* (*il2cpp_method_get_name_t)(void*);
typedef uint32_t (*il2cpp_method_get_flags_t)(void*, uint32_t*);
typedef uint32_t (*il2cpp_method_get_param_count_t)(void*);
typedef void*    (*il2cpp_method_get_return_type_t)(void*);
typedef int      (*il2cpp_type_get_type_t)(void*);
typedef void*    (*il2cpp_class_from_type_t)(void*);
typedef void*    (*il2cpp_runtime_invoke_t)(void*, void*, void**, void**);
typedef void     (*il2cpp_free_t)(void*);

static il2cpp_domain_get_t              p_domain_get;
static il2cpp_thread_attach_t           p_thread_attach;
static il2cpp_domain_get_assemblies_t   p_get_assemblies;
static il2cpp_assembly_get_image_t      p_get_image;
static il2cpp_image_get_name_t          p_image_name;
static il2cpp_image_get_class_count_t   p_class_count;
static il2cpp_image_get_class_t         p_get_class;
static il2cpp_class_get_name_t          p_class_name;
static il2cpp_class_get_fields_t        p_get_fields;
static il2cpp_field_get_type_t          p_field_type;
static il2cpp_type_get_name_t           p_type_name;
static il2cpp_class_get_methods_t       p_get_methods;
static il2cpp_method_get_name_t         p_method_name;
static il2cpp_method_get_flags_t        p_method_flags;
static il2cpp_method_get_param_count_t  p_param_count;
static il2cpp_method_get_return_type_t  p_return_type;
static il2cpp_type_get_type_t           p_type_kind;
static il2cpp_class_from_type_t         p_class_from_type;
static il2cpp_runtime_invoke_t          p_invoke;
static il2cpp_free_t                    p_free;

static void  *g_resolvedGetter;   // MethodInfo* for the promise's static Resolved getter
static BYTE   backup_scan[32];


static int ends_with(const char *s, const char *suf)
{
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && strcmp(s + (ls - lf), suf) == 0;
}

static char *type_name_dup(void *type)
{
    // il2cpp_type_get_name returns a heap string; copy into a small static-free buffer via strdup.
    char *n = p_type_name(type);
    if (!n) return NULL;
    char *copy = _strdup(n);
    if (p_free) p_free(n);
    return copy;
}

// True if klass has a field whose type name equals `full` or ends with `.suffix`.
static int class_has_field_type(void *klass, const char *full, const char *dotsuffix)
{
    void *iter = NULL, *field;
    int found = 0;
    while ((field = p_get_fields(klass, &iter)) != NULL)
    {
        void *ft = p_field_type(field);
        if (!ft) continue;
        char *tn = type_name_dup(ft);
        if (!tn) continue;
        if (strcmp(tn, full) == 0 || ends_with(tn, dotsuffix)) found = 1;
        free(tn);
        if (found) break;
    }
    return found;
}

static BOOL ResolveApi(HMODULE ga)
{
    p_domain_get      = (il2cpp_domain_get_t)            GetProcAddress(ga, "il2cpp_domain_get");
    p_thread_attach   = (il2cpp_thread_attach_t)         GetProcAddress(ga, "il2cpp_thread_attach");
    p_get_assemblies  = (il2cpp_domain_get_assemblies_t) GetProcAddress(ga, "il2cpp_domain_get_assemblies");
    p_get_image       = (il2cpp_assembly_get_image_t)    GetProcAddress(ga, "il2cpp_assembly_get_image");
    p_image_name      = (il2cpp_image_get_name_t)        GetProcAddress(ga, "il2cpp_image_get_name");
    p_class_count     = (il2cpp_image_get_class_count_t) GetProcAddress(ga, "il2cpp_image_get_class_count");
    p_get_class       = (il2cpp_image_get_class_t)       GetProcAddress(ga, "il2cpp_image_get_class");
    p_class_name      = (il2cpp_class_get_name_t)        GetProcAddress(ga, "il2cpp_class_get_name");
    p_get_fields      = (il2cpp_class_get_fields_t)      GetProcAddress(ga, "il2cpp_class_get_fields");
    p_field_type      = (il2cpp_field_get_type_t)        GetProcAddress(ga, "il2cpp_field_get_type");
    p_type_name       = (il2cpp_type_get_name_t)         GetProcAddress(ga, "il2cpp_type_get_name");
    p_get_methods     = (il2cpp_class_get_methods_t)     GetProcAddress(ga, "il2cpp_class_get_methods");
    p_method_name     = (il2cpp_method_get_name_t)       GetProcAddress(ga, "il2cpp_method_get_name");
    p_method_flags    = (il2cpp_method_get_flags_t)      GetProcAddress(ga, "il2cpp_method_get_flags");
    p_param_count     = (il2cpp_method_get_param_count_t)GetProcAddress(ga, "il2cpp_method_get_param_count");
    p_return_type     = (il2cpp_method_get_return_type_t)GetProcAddress(ga, "il2cpp_method_get_return_type");
    p_type_kind       = (il2cpp_type_get_type_t)         GetProcAddress(ga, "il2cpp_type_get_type");
    p_class_from_type = (il2cpp_class_from_type_t)       GetProcAddress(ga, "il2cpp_class_from_type");
    p_invoke          = (il2cpp_runtime_invoke_t)        GetProcAddress(ga, "il2cpp_runtime_invoke");
    p_free            = (il2cpp_free_t)                  GetProcAddress(ga, "il2cpp_free");

    return p_domain_get && p_get_assemblies && p_get_image && p_image_name && p_class_count &&
           p_get_class && p_get_fields && p_field_type && p_type_name && p_get_methods &&
           p_method_name && p_method_flags && p_param_count && p_return_type && p_type_kind &&
           p_class_from_type && p_invoke;
}

static void* FindImage(void *domain, const char *wantName)
{
    size_t n = 0;
    void **asms = p_get_assemblies(domain, &n);
    for (size_t i = 0; i < n; i++)
    {
        void *img = p_get_image(asms[i]);
        if (!img) continue;
        const char *nm = p_image_name(img);
        if (nm && strcmp(nm, wantName) == 0) return img;
    }
    return NULL;
}

//
// The detour: return a freshly-resolved promise instead of running the scan. Instance method ABI is
// (RCX=this, RDX=MethodInfo*); we ignore both. Re-invoking the getter each call avoids holding a GC
// reference. If the getter ever throws/returns null we return null -- the managed patch's fallback
// was to let the original run, but by the time we're detoured that's not an option, so null it is
// (boot's .Then on a null promise is still better than a guaranteed hash-mismatch rejection).
//
static void* ScanHook(void *self, void *methodInfo)
{
    (void)self; (void)methodInfo;
    if (!g_resolvedGetter) return NULL;
    void *exc = NULL;
    return p_invoke(g_resolvedGetter, NULL, NULL, &exc);
}

void PatchMemoryIntegrityCheck(void)
{
    HMODULE ga = NULL;
    while (!ga) { ga = GetModuleHandleA("GameAssembly.dll"); if (!ga) Sleep(100); }

    if (!ResolveApi(ga)) { Log("[MEMCHECK] missing il2cpp exports -- aborting"); return; }

    void *domain = NULL;
    for (int i = 0; i < 600 && !domain; i++) { domain = p_domain_get(); if (!domain) Sleep(100); }
    if (!domain) { Log("[MEMCHECK] il2cpp domain never came up"); return; }
    if (p_thread_attach) p_thread_attach(domain);

    // Assembly-CSharp holds the scanner. Retry through early init.
    void *img = NULL;
    for (int i = 0; i < 100 && !img; i++) { img = FindImage(domain, "Assembly-CSharp.dll"); if (!img) Sleep(100); }
    if (!img) { Log("[MEMCHECK] Assembly-CSharp.dll image not found"); return; }

    //
    // Find the scanner class: has BOTH a Thread field and a CancellationTokenSource field.
    //
    size_t ccount = p_class_count(img);
    void *scanner = NULL;

    for (size_t i = 0; i < ccount; i++)
    {
        void *c = p_get_class(img, i);
        if (!c) continue;

        if (class_has_field_type(c, "System.Threading.Thread", ".Thread") &&
            class_has_field_type(c, "System.Threading.CancellationTokenSource", ".CancellationTokenSource"))
        {
            const char *cn = p_class_name(c);
            Log("[MEMCHECK] scanner candidate: %s", cn ? cn : "?");
            scanner = c;   // keep last; log all so ambiguity is visible
        }
    }

    if (!scanner)
    {
        Log("[MEMCHECK] no class with Thread+CancellationTokenSource found -- scanner not identified");
        return;
    }

    //
    // Scan-start method: public, instance, 0-param, non-void. Log every candidate; pick the sole one.
    //
    void *scanMethod = NULL;
    void *promiseClass = NULL;
    int candidates = 0;

    void *iter = NULL, *m;
    while ((m = p_get_methods(scanner, &iter)) != NULL)
    {
        uint32_t iflags = 0;
        uint32_t f = p_method_flags(m, &iflags);
        if (f & METHOD_ATTRIBUTE_STATIC) continue;
        if ((f & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) != METHOD_ATTRIBUTE_PUBLIC) continue;
        if (p_param_count(m) != 0) continue;

        void *rt = p_return_type(m);
        if (!rt || p_type_kind(rt) == IL2CPP_TYPE_VOID) continue;

        const char *mn = p_method_name(m);
        char *rtn = type_name_dup(rt);
        Log("[MEMCHECK] scan-start candidate: %s() -> %s", mn ? mn : "?", rtn ? rtn : "?");
        if (rtn) free(rtn);

        scanMethod = m;
        promiseClass = p_class_from_type(rt);
        candidates++;
    }

    if (!scanMethod)
    {
        Log("[MEMCHECK] no public instance 0-param non-void method on scanner -- cannot hook");
        return;
    }
    if (candidates > 1)
        Log("[MEMCHECK] WARNING %d scan-start candidates; using the last -- may be wrong", candidates);

    //
    // Resolved-promise getter: any image, static, special-name (property getter), 0-param, returns
    // the promise class, name not ending _k__BackingField. (Managed found exactly one.)
    //
    size_t na = 0;
    void **asms = p_get_assemblies(domain, &na);
    int getters = 0;

    for (size_t ai = 0; ai < na && getters < 1; ai++)
    {
        void *im = p_get_image(asms[ai]);
        if (!im) continue;
        size_t cc = p_class_count(im);
        for (size_t ci = 0; ci < cc && getters < 1; ci++)
        {
            void *c = p_get_class(im, ci);
            if (!c) continue;
            void *it = NULL, *mm;
            while ((mm = p_get_methods(c, &it)) != NULL)
            {
                uint32_t iflags = 0;
                uint32_t f = p_method_flags(mm, &iflags);
                if (!(f & METHOD_ATTRIBUTE_STATIC)) continue;
                if (!(f & METHOD_ATTRIBUTE_SPECIAL_NAME)) continue;
                if (p_param_count(mm) != 0) continue;

                void *rt = p_return_type(mm);
                if (!rt || p_class_from_type(rt) != promiseClass) continue;

                const char *mn = p_method_name(mm);
                if (mn && ends_with(mn, "_k__BackingField")) continue;

                Log("[MEMCHECK] resolved-promise getter: %s.%s", p_class_name(c), mn ? mn : "?");
                g_resolvedGetter = mm;
                getters++;
                break;
            }
        }
    }

    if (!g_resolvedGetter)
    {
        Log("[MEMCHECK] no static Resolved getter returning the promise type -- cannot build a resolved promise");
        return;
    }

    // Sanity: make sure invoking the getter yields a non-null object before we commit the detour.
    void *exc = NULL;
    void *test = p_invoke(g_resolvedGetter, NULL, NULL, &exc);
    if (!test || exc)
    {
        Log("[MEMCHECK] Resolved getter returned null/threw -- not hooking (would hand boot a null promise)");
        return;
    }

    void *code = *(void **)scanMethod;   // MethodInfo.methodPointer
    Log("[MEMCHECK] scan-start MethodInfo=%p code=%p", scanMethod, code);
    if (!code) { Log("[MEMCHECK] scan-start has no compiled body"); return; }

    // Replace-only (we never call the original), so a blind 14-byte overwrite is safe.
    if (InstallDetour(code, ScanHook, backup_scan, NULL))
        Log("[MEMCHECK] native memory integrity scan skipped (scan-start -> resolved promise)");
    else
        Log("[MEMCHECK] failed to install scan-start detour");
}
