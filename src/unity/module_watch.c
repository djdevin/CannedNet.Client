#include "common.h"

#include "module_watch.h"

#include "logger.h"
#include "process.h"



void WatchModules()
{
    Log(
        "[MODULE WATCH] Started"
    );


    // One full dump for reference, then only announce the two modules we care about as they appear
    // and stop -- the old every-10s full dump buried the actual hook diagnostics.
    DumpLoadedModules();


    BOOL sawGame = FALSE;
    BOOL sawUnity = FALSE;


    while(!sawGame || !sawUnity)
    {
        if(!sawGame && GetModuleHandleA("GameAssembly.dll"))
        {
            sawGame = TRUE;
            Log("[MODULE WATCH] GameAssembly.dll loaded");
        }

        if(!sawUnity && GetModuleHandleA("UnityPlayer.dll"))
        {
            sawUnity = TRUE;
            Log("[MODULE WATCH] UnityPlayer.dll loaded");
        }

        Sleep(500);
    }


    Log(
        "[MODULE WATCH] game modules present, watcher done"
    );
}