#pragma once

#include "common.h"

typedef int (WSAAPI *connect_t)(
    SOCKET,
    const struct sockaddr *,
    int
);

extern connect_t real_connect;
extern connect_t original_connect;

extern BYTE backup_connect[14];

int WSAAPI hook_connect(
    SOCKET,
    const struct sockaddr *,
    int
);