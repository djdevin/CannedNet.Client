#pragma once

// Detours UnityEngine.Application.Quit() / Quit(int) to log the managed caller and (optionally)
// suppress the shutdown. See src/unity/quit_trace.c.
void PatchQuitTrace(void);

// Call-through hooks on kernel32!ExitProcess / !TerminateProcess that log who tore the process
// down. Installed by PatchQuitTrace; separate entry point so it can be used standalone.
void HookProcessExit(void);
