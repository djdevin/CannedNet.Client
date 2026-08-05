#pragma once

#include "common.h"

#define CONFIG_FILE "redirector.json"
#define MAX_REDIRECTS 64
#define MAX_REWRITES 32
#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 443

// Static-IP redirect (used only by the disabled connect hook; DNS uses host rewrite below).
extern char redirect_ip[16];
extern int redirect_port;

extern char *redirect_domains[MAX_REDIRECTS];
extern int redirect_count_config;

// Host rewrite pairs: a DNS lookup for exactly <from> is resolved as <to> instead, so real DNS
// returns the target's current (possibly dynamic) IP.
extern char *rewrite_from[MAX_REWRITES];
extern char *rewrite_to[MAX_REWRITES];
extern int rewrite_count;

void LoadConfig(void);