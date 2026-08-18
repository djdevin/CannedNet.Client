#pragma once
#include <windows.h>

// Unlink `self` from the PEB loader's three module lists so anything that walks the loaded-module
// list (GetModuleHandle, CreateToolhelp32Snapshot's module snapshot, and -- the point here -- a
// protector's periodic anti-tamper scan) no longer sees redirector.dll. The DLL stays mapped and all
// its hooks/threads keep running; only its visibility in the loader lists is removed. See
// src/memory/module_hide.c.
void HideModuleFromPeb(HMODULE self);
