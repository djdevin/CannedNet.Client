#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"psapi.lib")

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif