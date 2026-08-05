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

        HANDLE thread = CreateThread(
            NULL,
            0,
            HookThread,
            NULL,
            0,
            NULL
        );

        if(thread)
            CloseHandle(thread);
    }

    return TRUE;
}