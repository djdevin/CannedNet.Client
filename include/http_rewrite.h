#pragma once

#include "common.h"

// Installs the HTTP-layer host rewrite: hooks BestHTTP.HTTPManager.SendRequest(HTTPRequest) and
// rewrites the request's Uri (ns.rec.net -> ns.recflare.net) so the URL, TLS SNI and Host header all
// carry the target host -- a genuine request to the alternate backend, not just a redirected IP.
// Waits for the il2cpp runtime; safe to call on its own thread. No-op if no rewrite pairs configured.
void PatchHttpHostRewrite(void);
