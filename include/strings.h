#pragma once

#include "common.h"

int ShouldRedirect(const char *host);

// If host exactly matches a configured rewrite pair's <from>, writes <to> into out (up to outlen)
// and returns 1; otherwise returns 0 and leaves out untouched.
// Example: host "ns.rec.net", from "ns.rec.net", to "ns.recflare.net" -> "ns.recflare.net".
int RewriteHost(const char *host, char *out, size_t outlen);