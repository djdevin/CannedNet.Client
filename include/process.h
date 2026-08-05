#pragma once

#include "common.h"

BOOL IsGameProcess(void);

void LogProcessInfo(void);

void DumpLoadedModules(void);

void LogStack(void);

LONG WINAPI MyExceptionHandler(EXCEPTION_POINTERS *e);