#pragma once

//
// Hardware-breakpoint hooks: function interception that writes ZERO bytes.
//
// Every hook in this project so far is an inline detour -- 14+ bytes overwritten at the target's
// entry. Any integrity check that hashes GameAssembly.dll's .text sees those edits. On the
// recflare-client-unstable build (2025-04-29) the session dies ~35s in with a hard 0xC0000005 inside
// the Themida-wrapped RecRoom.exe.dll, which is very likely a NATIVE integrity check reacting to
// exactly that (see memory note unstable-build-identity-rvas.md).
//
// A hardware breakpoint lives in the CPU's debug registers instead of in the code, so the target's
// bytes stay pristine and no memory scan -- managed or native -- can see the hook.
//
// Cost/limits (why this isn't the default everywhere):
//   * There are only DR0-DR3, so a hard cap of 4 hooks. We spend 3 on the GameAssembly.dll targets
//     and leave ws2_32!getaddrinfo as a normal inline detour (a system DLL the game's own integrity
//     check has no reason to hash), keeping one slot free.
//   * Debug registers are PER-THREAD, so they must be applied to every thread that could reach the
//     target -- including threads created later (BestHTTP spins up its own). HwbpInit starts a
//     watcher that applies the current register set to any thread it hasn't seen yet.
//
// -------------------------------------------------------------------------------------------
// STATUS: WORKS. Verified on recflare-client-unstable (2025-04-29) with `"useHwbp": true` --
// 176 traps and 77 URL rewrites in one session, and the self-test (arming a function inside this
// DLL) passes. Default is nonetheless OFF (`use_hwbp = 0`): it makes no behavioural difference
// versus inline detours (the crash was proven NOT to be tamper detection), and it costs a thread
// suspend/resume storm, so the simpler path wins.
//
// Two things had to be right, both of which cost a lot of debugging:
//   * Arming: Dr0 reads back as the target VA and Dr7 as 0x415 (that is our 0x15 plus bit 10,
//     which always reads as 1 -- not a bug).
//   * The protector inside RecRoom.exe.dll ZEROES Dr0-Dr3 a few seconds in (Dr0 -> 0, Dr7 left
//     alone). Re-arming EVERY thread EVERY pass -- not just newly seen ones -- defeats that.
//   * Ordering: HwbpInit must run EARLY (it is kicked off from HwbpSelfTest right after the crash
//     handler). Starting the engine lazily at first-hook time was the real reason for a long
//     stretch of "armed but never fires" results -- threads were created before the watcher ran.
//
// Always HwbpDisarm() a slot you are done with, or the watcher keeps suspending every thread in the
// process five times a second forever.
// -------------------------------------------------------------------------------------------
#define HWBP_MAX 4

// Slot assignment (one per DR register).
#define HWBP_SLOT_SSL     0
#define HWBP_SLOT_HTTP    1
#define HWBP_SLOT_PHOTON  2
// slot 3 intentionally free

// Install the VEH and start the per-thread applier. Safe to call more than once.
BOOL HwbpInit(void);

// Point `slot` at `target`; when any thread executes `target`, control transfers to `hook` with the
// register state (and therefore the arguments and return address) untouched. Returns FALSE if the
// slot is out of range. Applying to already-running threads happens here; new threads are picked up
// by the watcher.
BOOL HwbpAdd(int slot, void *target, void *hook);

// Let THIS thread execute `slot`'s target once without trapping. A call-through hook must call this
// immediately before invoking the original, otherwise the call re-triggers the breakpoint and
// recurses forever. Per-thread, one-shot, and consumed by the next hit.
void HwbpSkipOnce(int slot);

// Arm the spare slot on a function inside this DLL and call it from a fresh thread, to establish
// whether hardware breakpoints function in this process at all. Logs SELF-TEST PASSED/FAILED.
// Runs regardless of use_hwbp -- it only touches our own code, never the game's.
void HwbpSelfTest(void);

// Release a slot and push the cleared debug registers to every thread. With no slots left armed the
// watcher stops suspending threads entirely, so always disarm what you no longer need.
void HwbpDisarm(int slot);
