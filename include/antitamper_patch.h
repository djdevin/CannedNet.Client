#ifndef ANTITAMPER_PATCH_H
#define ANTITAMPER_PATCH_H

// Suppresses the client's anti-tamper report funnel (build 2025-04-29). Every tamper detection --
// ImageSignature (signed CDN URL check), Inject, UnknownDll, Memory_Hash_Mismatch, etc. -- routes
// through one static method that creates a "Hile" warning (POST api/PlayerReporting/v1/hile) and can
// force-quit. Neutralizing it stops the ~30s lockup/exit our own patches + recflare's placeholder URL
// signatures would otherwise trigger.
void PatchAntiTamper(void);

#endif
