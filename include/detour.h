#pragma once

#include "common.h"

int InstallDetour(
    LPVOID target,
    LPVOID hook,
    BYTE *backup,
    LPVOID *outTrampoline
);