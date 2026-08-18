#ifndef RETSPOOF_H
#define RETSPOOF_H

#include "common.h"

//
// Return-address spoofing for il2cpp utility calls (il2cpp_string_new, il2cpp_object_new, Uri..ctor,
// get_Uri/set_Uri, ...). These are called from inside our hooks (http_rewrite.c, photon_patch.c), which
// means the CPU pushes a return address inside redirector.dll before jumping to them -- so for the
// duration of that call, any stack walk over the calling thread sees an unrecognized module
// (redirector.dll) on the stack. This is exactly the kind of signal an anti-tamper stack-walk check
// looks for (see the ~30s freeze/crash: GameAssembly.dll rewrites hooked methods into stack-exhaustion
// poison once it detects us -- memory note unstable-build-identity-rvas.md).
//
// SpoofCall4 calls a function with the return address the CPU sees replaced by a "jmp qword ptr [rbx]"
// gadget scanned out of the target's own module, so the call looks -- from the stack's perspective --
// like it originated from inside that module instead of from us. See retspoof.asm for the mechanics.
//

// Scans [mod's image] for a usable gadget and caches it. Safe to call once GameAssembly's code has
// decrypted (this build's packer XOR-decrypts .text shortly after mapping -- see CLAUDE.md). Logs the
// found address, or logs a failure and leaves spoofing unavailable (SpoofCall4 falls back to a direct
// call in that case). Returns 1 on success, 0 otherwise.
int InitRetSpoof(HMODULE mod);

// True once InitRetSpoof has found a usable gadget.
int RetSpoofReady(void);

// Waits for GameAssembly.dll to appear and its code to decrypt, then resolves the gadget. Intended to
// run on its own thread (mirrors the WaitForCode pattern in ssl_patch.c / http_rewrite.c), started
// early so the gadget is ready well before real traffic starts flowing through the hooks that use it.
DWORD WINAPI PatchRetSpoof(LPVOID param);

// Calls target(a1, a2, a3, a4) with a spoofed return address (see above). Pad unused trailing
// arguments with 0. Falls back to a direct call if no gadget has been resolved yet.
uint64_t SpoofCall4(void *target, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);

#endif
