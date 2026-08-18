#include "common.h"
#include "module_hide.h"
#include "logger.h"

//
// Hide our injected DLL from the PEB loader lists.
//
// The Themida assertion that ends the session fires on a consistent ~35s cadence, never earlier, and
// is invariant to how we launch (suspended vs running) and to whether we patch any code (inline vs
// hardware breakpoints vs nothing). The one thing constant across every one of those tests is that
// redirector.dll is present in the module list. A periodic anti-tamper scan that walks the loaded
// modules and flags an unexpected DLL matches that fingerprint exactly.
//
// Every loaded module is described by one LDR_DATA_TABLE_ENTRY that is simultaneously a member of the
// PEB loader's three doubly-linked lists (load order, memory order, init order). Unlinking that entry
// from all three removes the module from every standard enumeration without unmapping it -- our code,
// threads and hooks are unaffected because they were resolved at load time and don't depend on the
// list membership.
//
// x64 struct offsets (stable across modern Windows 10/11):
//   PEB:                 gs:[0x60]
//   PEB.Ldr:             +0x18  -> PEB_LDR_DATA*
//   PEB_LDR_DATA.InLoadOrderModuleList:  +0x10  (list head; entries linked at LDR entry +0x00)
//   LDR_DATA_TABLE_ENTRY.InLoadOrderLinks:          +0x00
//   LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks:        +0x10
//   LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks:+0x20
//   LDR_DATA_TABLE_ENTRY.DllBase:                   +0x30
//   LDR_DATA_TABLE_ENTRY.BaseDllName (UNICODE_STRING.Buffer at +0x08): +0x58
//

typedef struct _LIST_ENTRY_X { struct _LIST_ENTRY_X *Flink, *Blink; } LIST_ENTRY_X;

static void UnlinkOne(LIST_ENTRY_X *e)
{
    // Standard doubly-linked-list removal. Point it at itself afterwards so a stray re-walk of the
    // (now detached) entry can't crash.
    if (!e || !e->Flink || !e->Blink) return;
    e->Blink->Flink = e->Flink;
    e->Flink->Blink = e->Blink;
    e->Flink = e;
    e->Blink = e;
}

void HideModuleFromPeb(HMODULE self)
{
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    if (!peb) { Log("[HIDE] no PEB"); return; }

    BYTE *ldr = *(BYTE **)(peb + 0x18);
    if (!ldr) { Log("[HIDE] no PEB.Ldr"); return; }

    LIST_ENTRY_X *head = (LIST_ENTRY_X *)(ldr + 0x10);   // InLoadOrderModuleList
    for (LIST_ENTRY_X *cur = head->Flink; cur && cur != head; cur = cur->Flink)
    {
        BYTE *entry = (BYTE *)cur;                       // InLoadOrderLinks is at offset 0 of the entry
        HMODULE dllBase = *(HMODULE *)(entry + 0x30);
        if (dllBase != self) continue;

        UnlinkOne((LIST_ENTRY_X *)(entry + 0x00));       // InLoadOrderLinks
        UnlinkOne((LIST_ENTRY_X *)(entry + 0x10));       // InMemoryOrderLinks
        UnlinkOne((LIST_ENTRY_X *)(entry + 0x20));       // InInitializationOrderLinks

        Log("[HIDE] redirector.dll unlinked from PEB loader lists (base=%p) -- hidden from module walks",
            (void *)self);
        return;
    }

    Log("[HIDE] own module not found in loader list (base=%p) -- nothing hidden", (void *)self);
}
