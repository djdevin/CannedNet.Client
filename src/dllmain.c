#include "common.h"

#include "logger.h"
#include "process.h"
#include "hook_manager.h"


BOOL WINAPI DllMain(
    HINSTANCE hinst,
    DWORD reason,
    LPVOID reserved
)
{
    if(reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinst);

        // DIAGNOSTIC breadcrumb (unconditional, before any gate): proves our proxy actually loaded and
        // into which process. Written next to the host EXE via raw kernel32 calls (loader-lock safe).
        {
            char host[MAX_PATH];
            DWORD hn = GetModuleFileNameA(NULL, host, sizeof(host));
            char marker[MAX_PATH];
            char dir[MAX_PATH];
            strcpy_s(dir, sizeof(dir), host);
            char *slash = strrchr(dir, '\\');
            if(slash) *(slash + 1) = 0; else dir[0] = 0;
            sprintf_s(marker, sizeof(marker), "%srr_proxy_attach_%lu.txt", dir, GetCurrentProcessId());
            HANDLE hf = CreateFileA(marker, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hf != INVALID_HANDLE_VALUE)
            {
                DWORD wr;
                WriteFile(hf, host, hn, &wr, NULL);
                CloseHandle(hf);
            }
        }

        // Pass our own module base to the hook thread so it can (optionally) unlink us from the PEB
        // loader lists once config is read.
        HANDLE thread = CreateThread(
            NULL,
            0,
            HookThread,
            (LPVOID)hinst,
            0,
            NULL
        );

        if(thread)
            CloseHandle(thread);
    }

    return TRUE;
}