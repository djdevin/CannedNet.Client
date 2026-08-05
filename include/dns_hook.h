#pragma once

#include "common.h"

typedef int (WSAAPI *getaddrinfo_t)(
    PCSTR,
    PCSTR,
    const ADDRINFOA *,
    PADDRINFOA *
);

typedef struct hostent *(WSAAPI *gethostbyname_t)(
    const char *
);

extern getaddrinfo_t real_getaddrinfo;
extern getaddrinfo_t original_getaddrinfo;

extern gethostbyname_t real_gethostbyname;

extern BYTE backup_getaddrinfo[32];   // holds whole stolen instructions (>= 14 bytes)

int WSAAPI hook_getaddrinfo(
    PCSTR,
    PCSTR,
    const ADDRINFOA *,
    PADDRINFOA *
);

struct hostent *WSAAPI hook_gethostbyname(
    const char *
);