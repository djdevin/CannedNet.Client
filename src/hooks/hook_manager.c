#include "common.h"

#include "hook_manager.h"

#include "logger.h"
#include "config.h"
#include "process.h"

#include "dns_hook.h"
#include "connect_hook.h"

#include "detour.h"

#include "module_watch.h"
#include "ssl_patch.h"
#include "http_rewrite.h"
#include "memcheck_patch.h"
#include "eac_patch.h"



static BOOL unity_loaded = FALSE;



//
// Wait until UnityPlayer.dll exists. Bounded: our version.dll also loads into non-game processes
// (EAC launcher/bootstrap, crash handler) where UnityPlayer never appears -- those must give up and
// let the thread exit instead of spinning forever. Returns FALSE if Unity never showed up.
//

#define UNITY_WAIT_MS 60000

static BOOL WaitForUnity()
{
    Log(
        "[UNITY] Waiting for UnityPlayer.dll..."
    );


    for(int waited = 0; waited < UNITY_WAIT_MS; waited += 100)
    {
        if(GetModuleHandleA("UnityPlayer.dll"))
        {
            unity_loaded = TRUE;

            Log(
                "[UNITY] UnityPlayer.dll detected"
            );

            return TRUE;
        }

        Sleep(100);
    }


    Log(
        "[UNITY] UnityPlayer.dll not found after %d ms -- not a game process, exiting hook thread",
        UNITY_WAIT_MS
    );

    return FALSE;
}




//
// Install all hooks
//

BOOL InstallHooks()
{
    HMODULE ws2 =
        GetModuleHandleA(
            "ws2_32.dll"
        );


    if(!ws2)
    {
        Log(
            "[HOOK] ws2_32.dll missing"
        );

        return FALSE;
    }


    Log(
        "[HOOK] ws2_32.dll loaded"
    );



    //
    // Resolve functions
    //

    real_getaddrinfo =
        (getaddrinfo_t)GetProcAddress(
            ws2,
            "getaddrinfo"
        );


    real_gethostbyname =
        (gethostbyname_t)GetProcAddress(
            ws2,
            "gethostbyname"
        );


    real_connect =
        (connect_t)GetProcAddress(
            ws2,
            "connect"
        );



    Log(
        "[ADDR] getaddrinfo=%p",
        real_getaddrinfo
    );


    Log(
        "[ADDR] gethostbyname=%p",
        real_gethostbyname
    );


    Log(
        "[ADDR] connect=%p",
        real_connect
    );



    //
    // Install DNS hook
    //

    if(real_getaddrinfo)
    {
        Log(
            "[HOOK] Installing getaddrinfo"
        );


        if(
            InstallDetour(
                real_getaddrinfo,
                hook_getaddrinfo,
                backup_getaddrinfo,
                (LPVOID*)&original_getaddrinfo
            )
        )
        {
            Log(
                "[HOOK] getaddrinfo installed"
            );
        }
        else
        {
            Log(
                "[HOOK] getaddrinfo failed"
            );
        }
    }
    else
    {
        Log(
            "[HOOK] getaddrinfo missing"
        );
    }



    //
    // Connect hook will be enabled later
    //
    // Currently disabled exactly like
    // your original test build.
    //



    Log(
        "===================================="
    );

    Log(
        "[STATUS] DNS REDIRECT ACTIVE"
    );

    Log(
        "===================================="
    );


    return TRUE;
}




//
// Main redirector thread
//

DWORD WINAPI HookThread(
    LPVOID param
)
{
    //
    // Bail before AllocConsole/InitLogger in non-game processes. RecRoom.exe spawns
    // UnityCrashHandler64.exe out of the same folder, so our version.dll loads there too; without
    // this check every launch opened two debug consoles and left the crash handler spinning in
    // WaitForUnity for a minute. Nothing here belongs in that process anyway.
    //

    if(!IsGameProcess())
        return 0;


    InitConsole();

    InitLogger();


    SetUnhandledExceptionFilter(
        MyExceptionHandler
    );


    Log(
        "[THREAD] Hook thread started"
    );


    // Identify which process we're in (game vs EAC launcher vs crash handler).
    LogProcessInfo();



    //
    // Start module watcher
    //

    HANDLE moduleThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                WatchModules,
            NULL,
            0,
            NULL
        );


    if(moduleThread)
        CloseHandle(moduleThread);



    //
    // Load redirect config
    //

    LoadConfig();



    //
    // Wait for Unity. If this isn't the game process (EAC launcher, crash handler, ...), bail so we
    // don't spin forever or install hooks where they don't belong.
    //

    if(!WaitForUnity())
        return 0;



    Sleep(2000);



    //
    // Install hooks
    //

    if(!InstallHooks())
    {
        Log(
            "[HOOK] Installation failed"
        );

        return 1;
    }



    //
    // Memory-integrity scan neutralizer. Started FIRST among the il2cpp patches because the boot
    // step that awaits the scan can fire early -- its reflection search needs a head start so the
    // scan-start detour is in place before boot calls it. Without this, boot fails "Launch
    // validation failed" once our other hooks perturb GameAssembly memory.
    //

    HANDLE memThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                PatchMemoryIntegrityCheck,
            NULL,
            0,
            NULL
        );


    if(memThread)
        CloseHandle(memThread);



    //
    // TLS pinning bypass. Runs on its own thread because it waits for the il2cpp runtime to
    // finish init (GameAssembly.dll + il2cpp_domain_get) before it can resolve+detour the
    // BouncyCastle NotifyServerCertificate method. Without this, HTTPS to the redirected server
    // fails the handshake (mismatched/pinned cert).
    //

    HANDLE sslThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                PatchBestHTTPSSL,
            NULL,
            0,
            NULL
        );


    if(sslThread)
        CloseHandle(sslThread);



    //
    // HTTP-layer host rewrite (ns.rec.net -> ns.recflare.net in the request Uri). Own thread: like
    // the SSL patch it waits for the il2cpp runtime before resolving+hooking SendRequest.
    //

    HANDLE httpThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                PatchHttpHostRewrite,
            NULL,
            0,
            NULL
        );


    if(httpThread)
        CloseHandle(httpThread);



    //
    // EAC neutralizer (force readiness true + base64 challenge response). Own thread; waits for the
    // il2cpp runtime. Safe now that the memory-integrity scan is neutralized.
    //

    HANDLE eacThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                PatchEAC,
            NULL,
            0,
            NULL
        );


    if(eacThread)
        CloseHandle(eacThread);



    Log(
        "[THREAD] Redirector initialized"
    );


    return 0;
}