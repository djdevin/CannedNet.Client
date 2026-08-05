#include "common.h"

#include "logger.h"


void LogTLS(
    const char *event
)
{
    Log(
        "[TLS] %s",
        event ? event : "NULL"
    );
}