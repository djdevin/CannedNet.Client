#include "common.h"

#include "process.h"
#include "logger.h"



//
// version.dll gets loaded by every process launched from the game folder -- RecRoom.exe itself and
// UnityCrashHandler64.exe, which RecRoom spawns from the same directory. Only the game is worth
// hooking (and worth a console window: two AllocConsole calls = two debug windows on every launch).
//
BOOL IsGameProcess()
{
    char path[MAX_PATH];

    if(
        !GetModuleFileNameA(
            NULL,
            path,
            sizeof(path)
        )
    )
    {
        return FALSE;
    }


    char *slash = strrchr(
        path,
        '\\'
    );


    const char *exe =
        slash ? slash + 1 : path;


    return _stricmp(
        exe,
        "RecRoom.exe"
    ) == 0;
}




void LogProcessInfo()
{
    char path[MAX_PATH];


    GetModuleFileNameA(
        NULL,
        path,
        sizeof(path)
    );


    Log(
        "[PROCESS] %s",
        path
    );


    Log(
        "[PID] %lu",
        GetCurrentProcessId()
    );
}




void DumpLoadedModules()
{
    Log(
        "========== MODULE LIST =========="
    );


    HANDLE snap =
        CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE,
            GetCurrentProcessId()
        );


    if(snap == INVALID_HANDLE_VALUE)
    {
        Log(
            "[MODULE] Failed"
        );

        return;
    }



    MODULEENTRY32 me;

    me.dwSize =
        sizeof(me);



    if(Module32First(
        snap,
        &me
    ))
    {
        do
        {
            MODULEINFO info;


            if(GetModuleInformation(
                GetCurrentProcess(),
                me.hModule,
                &info,
                sizeof(info)
            ))
            {
                Log(
                    "[MODULE] %s Base=%p Size=%lu",
                    me.szModule,
                    info.lpBaseOfDll,
                    info.SizeOfImage
                );
            }
            else
            {
                Log(
                    "[MODULE] %s",
                    me.szModule
                );
            }


        } while(Module32Next(
            snap,
            &me
        ));
    }


    CloseHandle(
        snap
    );


    Log(
        "================================"
    );
}





void LogStack()
{
    void *frames[32];


    USHORT count =
        CaptureStackBackTrace(
            1,
            32,
            frames,
            NULL
        );


    Log(
        "[STACK] Frames=%d",
        count
    );


    for(
        int i = 0;
        i < count;
        i++
    )
    {
        Log(
            "[STACK] %p",
            frames[i]
        );
    }
}




LONG WINAPI MyExceptionHandler(
    EXCEPTION_POINTERS *e
)
{
    Log(
        "========== DLL CRASH =========="
    );


    Log(
        "[EXCEPTION] 0x%08X",
        e->ExceptionRecord->ExceptionCode
    );


    Log(
        "[ADDRESS] %p",
        e->ExceptionRecord->ExceptionAddress
    );


    LogStack();


    Log(
        "=============================="
    );


    return EXCEPTION_CONTINUE_SEARCH;
}