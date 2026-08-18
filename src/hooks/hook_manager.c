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
#include "photon_patch.h"
#include "quit_trace.h"
#include "filesig_patch.h"
#include "hwbp.h"
#include "antitamper_patch.h"
#include "crash_handler.h"
#include "module_hide.h"
#include "retspoof.h"



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

    if(!enable_dns)
    {
        // Safety net only: with the SendRequest host rewrite active the client already asks for real
        // *.recflare.net names. Skipping this leaves ZERO inline byte patches in the process, which
        // is how we test whether our patching is what the protector reacts to.
        Log("[HOOK] DNS hook disabled via config -- no inline patches will be installed");
    }
    else if(real_getaddrinfo)
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

    // Diagnostics are observers, but a first-in-chain VEH plus a probe that suspends the main
    // thread every 3s can themselves perturb a protected process -- keep them switchable so a
    // measurement can exclude them.
    if(enable_diag)
    {
        InstallCrashHandler();

        // Establish once per run whether hardware breakpoints are usable in this process at all.
        // Only touches our own code, so it is safe even with use_hwbp off (the default).
        HwbpSelfTest();

        // Watch for a main-thread stall.
        StartHangProbe();
    }
    else
    {
        Log("[DIAG] diagnostics disabled via config (no AV logger, no hang probe, no HWBP self-test)");
    }


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
    // Optionally unlink ourselves from the PEB loader lists. Best current guess at what Themida's
    // ~35s anti-tamper check flags: a foreign module in the loader list. Done right after config so
    // it happens before the game's periodic scans get going. `param` is our own HMODULE from DllMain.
    //
    if(hide_module)
        HideModuleFromPeb((HMODULE)param);

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
    // Return-address spoofing gadget scan. Started before every other il2cpp patch: http_rewrite.c and
    // photon_patch.c route their il2cpp utility calls (string_new, object_new, Uri..ctor, get/set_Uri)
    // through SpoofCall4 so those calls don't show redirector.dll on the stack. The scan itself only
    // takes tens of ms once GameAssembly's code is decrypted, but starting it first gives it the most
    // lead time before real traffic starts flowing through the hooks that depend on it. SpoofCall4
    // falls back to a plain call if the scan hasn't finished yet, so nothing blocks on this thread.
    //

    HANDLE spoofThread =
        CreateThread(
            NULL,
            0,
            PatchRetSpoof,
            NULL,
            0,
            NULL
        );


    if(spoofThread)
        CloseHandle(spoofThread);



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

    if(enable_ssl)
    {
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
    }
    else
    {
        Log("[HOOK] SSL bypass disabled via config -- skipping");
    }



    //
    // HTTP-layer host rewrite (ns.rec.net -> ns.recflare.net in the request Uri). Own thread: like
    // the SSL patch it waits for the il2cpp runtime before resolving+hooking SendRequest.
    //

    if(enable_http)
    {
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
    }
    else
    {
        Log("[HOOK] HTTP host rewrite disabled via config -- skipping");
    }



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



    //
    // Photon app-id injection. Own thread; waits for GameAssembly then detours the Photon connect seam
    // to fill in the operator's Photon Cloud app IDs (empty otherwise -> InvalidAuthentication ~30s in).
    //

    if(enable_photon)
    {
        HANDLE photonThread =
            CreateThread(
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)
                    PatchPhotonAppId,
                NULL,
                0,
                NULL
            );


        if(photonThread)
            CloseHandle(photonThread);
    }
    else
    {
        Log("[HOOK] Photon app-id injection disabled via config -- skipping");
    }



    //
    // File-signature-check neutraliser. Own thread; waits for GameAssembly then detours the
    // file_sig_check P/Invoke whose unresolved native pointer is what actually crashes the process
    // ~35s in (see src/unity/filesig_patch.c for the full evidence chain).
    //

    HANDLE fileSigThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                PatchFileSigCheck,
            NULL,
            0,
            NULL
        );


    if(fileSigThread)
        CloseHandle(fileSigThread);



    //
    // Anti-tamper report funnel suppression. Own thread; waits for GameAssembly then detours the tamper
    // funnel so ImageSignature (placeholder CDN sig) + our own hooks don't create a Hile warning that
    // POSTs api/PlayerReporting/v1/hile and force-quits ~30s in.
    //

    // TEMPORARILY DISABLED for crash isolation: does the 0xC0000005 go away without the funnel's
    // null-return?
    #if 0
    HANDLE antitamperThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                PatchAntiTamper,
            NULL,
            0,
            NULL
        );


    if(antitamperThread)
        CloseHandle(antitamperThread);
    #endif



    //
    // Application.Quit tracer. Own thread; waits for GameAssembly then detours both Quit overloads to
    // log the managed caller (map with il2cpp-tools/whatis.py) and, when "blockQuit" is set in
    // redirector.json, swallow the shutdown. This is what identifies WHO ends the session ~11s in --
    // Player.log stops at PhotonNetwork.Disconnect() without ever naming a reason.
    //

    // DISABLED: it did its job -- both Application.Quit overloads and TerminateProcess(self) NEVER
    // fire, so the session ends in a hard crash, not a requested exit. Leaving it on would add three
    // more inline patches to the very code the integrity scan is suspected of hashing, which would
    // pollute the memcheck experiment. Re-enable only to re-test the exit path.
    #if 0
    HANDLE quitThread =
        CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)
                PatchQuitTrace,
            NULL,
            0,
            NULL
        );


    if(quitThread)
        CloseHandle(quitThread);
    #endif



    Log(
        "[THREAD] Redirector initialized"
    );


    return 0;
}