#include "common.h"

#include "logger.h"


static FILE *logFile = NULL;


void InitConsole()
{
    AllocConsole();

    FILE *fp;

    freopen_s(
        &fp,
        "CONOUT$",
        "w",
        stdout
    );


    printf("\n");
    printf("==============================\n");
    printf(" RR Redirector Loaded\n");
    printf("==============================\n\n");
}


void InitLogger()
{
    char path[MAX_PATH];

    GetModuleFileNameA(
        NULL,
        path,
        sizeof(path)
    );


    char *slash = strrchr(
        path,
        '\\'
    );


    if(slash)
        *(slash + 1) = 0;


    //
    // Per-PID filename. version.dll is loaded into several processes (the game, the EAC
    // launcher/bootstrap, the crash handler); a shared redirector.log means they truncate each
    // other's output with "w". One file per process keeps the game's diagnostics intact.
    //
    char name[64];

    sprintf_s(
        name,
        sizeof(name),
        "redirector_%lu.log",
        GetCurrentProcessId()
    );


    strcat_s(
        path,
        sizeof(path),
        name
    );


    logFile = fopen(
        path,
        "w"
    );


    if(logFile)
    {
        fprintf(
            logFile,
            "==============================\n"
        );

        fprintf(
            logFile,
            " RR Redirector Loaded\n"
        );

        fprintf(
            logFile,
            "==============================\n\n"
        );


        fflush(logFile);
    }
}



void Log(
    const char *fmt,
    ...
)
{
    SYSTEMTIME st;

    GetLocalTime(
        &st
    );


    DWORD tid =
        GetCurrentThreadId();


    char buffer[4096];


    va_list args;

    va_start(
        args,
        fmt
    );


    vsprintf_s(
        buffer,
        sizeof(buffer),
        fmt,
        args
    );


    va_end(args);



    printf(
        "[%02d:%02d:%02d.%03d][TID %lu] %s\n",
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        tid,
        buffer
    );


    if(logFile)
    {
        fprintf(
            logFile,
            "[%02d:%02d:%02d.%03d][TID %lu] %s\n",
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds,
            tid,
            buffer
        );


        fflush(logFile);
    }
}