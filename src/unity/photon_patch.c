#include "common.h"
#include "photon_patch.h"
#include "logger.h"
#include "detour.h"
#include "config.h"
#include "retspoof.h"
#include "hwbp.h"

//
// Photon app-id injection (recflare-client-unstable, build 2025-04-29).
//
// The client authenticates to Photon Cloud (ns.exitgames.com) using AppSettings.AppIdRealtime/Voice/
// Chat. A self-hosted RecNet server can't hand out real Photon Cloud app IDs (they're account secrets),
// so with an empty app id the client's startup GetRegions fails "-2: Empty application id" ->
// InvalidAuthentication -> BootSequence error -> clean exit ~30s in. The old managed patcher solved this
// with PhotonPatches (inject app IDs client-side). We do the same natively: detour the concrete
// ConnectUsingSettings-style method IMJEOJBJIMB(AppSettings) [RVA 0x7BECE70, call-through] and, before
// the original runs, overwrite the app-id / region fields on the passed AppSettings object.
//
// AppSettings is a Photon SDK type (Photon.Realtime.AppSettings) not in the Cpp2IL dump; its instance-
// field offsets were discovered at runtime (pre-Fusion layout confirmed by the empty app-id slots +
// the "..._prod" AppVersion string):
//   AppIdRealtime @ 0x10  (empty -> the GetRegions "-2 Empty application id" failure)
//   AppIdChat     @ 0x18
//   AppIdVoice    @ 0x20
//   AppVersion    @ 0x28  ("20250424_prod")   UseNameServer(bool) @ 0x30
// We overwrite the three app-id string fields from redirector.json (photonRealtimeAppId / ChatAppId /
// VoiceAppId) with fresh il2cpp strings (il2cpp_string_new @ RVA 0x8D9EA0, from the signature scan;
// exports are stripped). The hook runs on the game's own il2cpp/GC thread, so allocation is safe.
//

#define PHOTON_CONNECT_RVA  0x7BECE70   // concrete IMJEOJBJIMB(AppSettings) -> bool
#define STRING_NEW_RVA      0x8D9EA0

#define APPID_REALTIME_OFF  0x10
#define APPID_CHAT_OFF      0x18
#define APPID_VOICE_OFF     0x20

typedef void* (*string_new_fn_t)(const char*);
typedef int   (*photon_connect_fn_t)(void *self, void *appSettings, void *methodInfo);

static string_new_fn_t     g_string_new;
static photon_connect_fn_t original_connect;
static BYTE                backup_connect[32];

// HWBP call-through shim -- see the same pattern in http_rewrite.c and hwbp.h.
static photon_connect_fn_t g_realConnect;
static int PhotonConnectViaHwbp(void *self, void *appSettings, void *mi)
{
    HwbpSkipOnce(HWBP_SLOT_PHOTON);
    return g_realConnect(self, appSettings, mi);
}

// SEH-safe printable-ASCII read (for the discovery dump).
static int SafeAscii(const char *p, char *out, int n)
{
    if (!p) return 0;
    __try {
        for (int j = 0; j < n - 1; j++) {
            char c = p[j];
            if (c == 0) { out[j] = 0; return 1; }
            if (c < 0x20 || c > 0x7e) return 0;
            out[j] = c;
        }
        out[n - 1] = 0; return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Read an il2cpp string object's ASCII (length@0x10, chars@0x14).
static int ReadStr(void *str, char *out, int cap)
{
    __try {
        if (!str) return -1;
        int len = *(int *)((BYTE *)str + 0x10);
        if (len < 0 || len >= cap) return -1;
        uint16_t *w = (uint16_t *)((BYTE *)str + 0x14);
        for (int i = 0; i < len; i++) out[i] = (w[i] < 0x80) ? (char)w[i] : '?';
        out[len] = 0;
        return len;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

// Overwrite one app-id string field if a value is configured; log before/after once.
static void SetAppId(void *appSettings, int off, const char *cfg, const char *label, int logIt)
{
    if (!cfg || !cfg[0]) return;
    __try {
        char before[128]; int had = ReadStr(*(void **)((BYTE *)appSettings + off), before, sizeof(before));
        void *ns = (void *)SpoofCall4(g_string_new, (uint64_t)cfg, 0, 0, 0);
        if (ns) {
            *(void **)((BYTE *)appSettings + off) = ns;
            if (logIt) Log("[PHOTON] %s +0x%02X: \"%s\" -> \"%s\"", label, off, had >= 0 ? before : "?", cfg);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (logIt) Log("[PHOTON] %s injection faulted", label);
    }
}

static int PhotonConnectHook(void *self, void *appSettings, void *mi)
{
    static int done = 0;
    int logIt = !done; done = 1;
    if (appSettings)
    {
        SetAppId(appSettings, APPID_REALTIME_OFF, photon_realtime_appid, "AppIdRealtime", logIt);
        SetAppId(appSettings, APPID_CHAT_OFF,     photon_chat_appid,     "AppIdChat",     logIt);
        SetAppId(appSettings, APPID_VOICE_OFF,    photon_voice_appid,    "AppIdVoice",    logIt);
    }
    return original_connect(self, appSettings, mi);
}

void PatchPhotonAppId(void)
{
    HMODULE ga = NULL;
    while (!ga) { ga = GetModuleHandleA("GameAssembly.dll"); if (!ga) Sleep(100); }

    g_string_new = (string_new_fn_t)((BYTE *)ga + STRING_NEW_RVA);

    BYTE *code = (BYTE *)ga + PHOTON_CONNECT_RVA;
    for (int i = 0; i < 600; i++) { if (code[0] != 0x00 && code[0] != 0xCC) break; Sleep(100); }
    Log("[PHOTON] connect(AppSettings) code=%p prologue=%02X %02X %02X %02X",
        code, code[0], code[1], code[2], code[3]);

    if (use_hwbp)
    {
        g_realConnect = (photon_connect_fn_t)code;
        if (HwbpAdd(HWBP_SLOT_PHOTON, code, PhotonConnectHook))
        {
            original_connect = PhotonConnectViaHwbp;
            Log("[PHOTON] app-id injection installed via HWBP (no bytes patched)");
            return;
        }
        Log("[PHOTON] HWBP arm failed -- falling back to inline detour");
    }

    if (InstallDetour(code, PhotonConnectHook, backup_connect, (LPVOID *)&original_connect))
        Log("[PHOTON] app-id injection hook installed on IMJEOJBJIMB(AppSettings)");
    else
        Log("[PHOTON] connect(AppSettings) detour refused -- app-id injection NOT active");
}
