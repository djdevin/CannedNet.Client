#pragma once

#include "common.h"

// Neutralizes the client's native memory-integrity scan, which otherwise fails boot with
// "Launch validation failed. Is Rec Room installed correctly?" because it hashes GameAssembly.dll's
// executable memory and our inline hooks (SendRequest, NotifyServerCertificate) change it.
//
// Mirrors the managed MemoryIntegrityPatch: find the scanner by signature (a class with both a
// Thread and a CancellationTokenSource field), detour its public 0-param scan-start method to return
// an already-resolved promise, so the boot step never sees a mismatch. All resolution is by
// signature at runtime -- no obfuscated names, survives per-build name rotation. Waits for the
// il2cpp runtime; safe on its own thread.
void PatchMemoryIntegrityCheck(void);
