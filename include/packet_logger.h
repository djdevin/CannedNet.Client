#pragma once

#include <stddef.h>

void LogPacket(
    const char *direction,
    const void *data,
    size_t size
);