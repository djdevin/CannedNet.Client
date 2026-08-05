#pragma once

#include "common.h"

// Neutralizes EasyAntiCheat integration so the client runs against the self-hosted server. Ports the
// managed EACPatches: (1) force EACManager's readiness check true, (2) make GenerateChallengeResponse
// return base64(challenge). Resolves EACManager by its (unobfuscated) name and the readiness method by
// signature (its obfuscated name rotates per build). Waits for the il2cpp runtime; safe on its own thread.
void PatchEAC(void);
