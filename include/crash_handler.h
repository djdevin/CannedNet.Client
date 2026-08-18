#pragma once

// Vectored AV logger: logs access violations as module+RVA (GA/UP/RR) with registers and a walk of
// the FAULTING thread's stack. First-chance and non-intrusive.
void InstallCrashHandler(void);

// Periodically samples Unity's main thread (RIP + stack) so a stall shows up as a repeating sample.
// See the comment block in src/debug/crash_handler.c.
void StartHangProbe(void);

// Unity's main thread id, published by the SendRequest hook the first time it runs (that hook
// executes on the main thread). Read by the hang probe; 0 until the first request.
extern volatile DWORD g_mainThreadId;
