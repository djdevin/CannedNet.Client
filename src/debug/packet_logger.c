#include "common.h"
#include "logger.h"


void LogPacket(
    const char *direction,
    const void *data,
    size_t size
)
{
    Log(
        "[PACKET] %s %zu bytes",
        direction ? direction : "UNKNOWN",
        size
    );


    //
    // Hex dumping can be added later
    //
    // Example:
    //
    // SEND:
    // 16 03 01 00 5A ...
    //
}