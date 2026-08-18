#ifndef PHOTON_PATCH_H
#define PHOTON_PATCH_H

// Injects the operator's Photon Cloud app IDs into the AppSettings the client hands to Photon at
// connect time (the self-hosted server can't supply real Photon Cloud app IDs). Build 2025-04-29.
void PatchPhotonAppId(void);

#endif
