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

// Photon Cloud app IDs injected into AppSettings at connect time (a self-hosted server can't supply
// real Photon Cloud app IDs). Empty string = not configured (that field is left untouched).
extern char photon_realtime_appid[64];
extern char photon_chat_appid[64];
extern char photon_voice_appid[64];

// Per-hook enable flags (all default 1/on). Lets a hook be disabled from redirector.json without a
// rebuild -- used to bisect which hook the anti-cheat's periodic runtime check is reacting to (the
// ~13-30s poison/crash -- see memory note unstable-build-identity-rvas.md). enable_spoof toggles
// whether SpoofCall4 (retspoof.c) actually uses the scanned gadget or always falls back to a plain
// call, so the return-address-spoofing change itself can be A/B tested the same way.
extern int enable_ssl;
extern int enable_http;
extern int enable_photon;
extern int enable_spoof;

// When set, the Application.Quit tracer (quit_trace.c) suppresses the shutdown instead of only
// logging its caller. Default 0 (log only) so a diagnostic build never silently blocks a legitimate
// exit -- set "blockQuit": 1 in redirector.json to keep the client alive through a spurious quit.
extern int block_quit;

// Use hardware breakpoints (debug registers, zero bytes written) instead of inline detours for the
// three GameAssembly.dll hooks, so a native integrity check hashing .text cannot see them. Default 1.
// Set "useHwbp": 0 in redirector.json to A/B against the old inline detours without a rebuild.
extern int use_hwbp;

// Install the ws2_32!getaddrinfo detour. Once the SendRequest host rewrite is active the client asks
// for real *.recflare.net names, which resolve on their own, so the DNS hook is only a safety net --
// turning it off ("enableDns": false) leaves ZERO inline byte patches anywhere in the process.
extern int enable_dns;

// Diagnostics: the vectored AV logger, the hang probe (which SUSPENDS the main thread every 3s) and
// the hardware-breakpoint self-test. All three are observers, but a first-in-chain VEH and periodic
// thread suspension are exactly the sort of thing that can perturb Themida's exception-driven code
// decryption -- so they must be switchable to keep them out of a measurement.
extern int enable_diag;

// Unlink redirector.dll from the PEB loader lists after load so a module-walking anti-tamper scan
// can't see our injected DLL. Default 1 (current best guess at what Themida's ~35s check flags).
extern int hide_module;

void LoadConfig(void);