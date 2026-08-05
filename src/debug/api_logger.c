#include "common.h"

#include "logger.h"


void LogAPIRequest(
    const char *method,
    const char *url
)
{
    Log(
        "[API] %s %s",
        method ? method : "UNKNOWN",
        url ? url : "NULL"
    );
}