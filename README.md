# RR Redirector (native)

A native (C/Win32) DLL that points the Rec Room client at a self-hosted server, **without any
managed mod loader**. BepInEx 6 and MelonLoader both fail on current Rec Room builds (crash in
`il2cpp_init` / loader trips the anti-cheat memory-integrity scan). This build sidesteps that: it is
loaded as a `version.dll` proxy and applies its patches — Winsock DNS, the HTTP request URL, TLS
pinning, the memory-integrity scan and EAC — directly in native code.

## How it works

1. **Loading vector.** `RecRoom.exe`/`UnityPlayer.dll` import `VERSION.dll` by name, and the loader
   searches the game folder before `System32`. We ship our own `version.dll` there; each of its 17
   exports is a thin wrapper that lazily loads the real system `version.dll` (by full path, so no
   recursion) and calls through, so the game keeps working. Its `DllMain` starts the hook thread.
   Loads very early, before `UnityPlayer.dll`. Self-contained — nothing else to ship.

   `RecRoom.exe` spawns `UnityCrashHandler64.exe` from the same folder, so our DLL loads there too.
   The hook thread checks the host executable and exits immediately in anything but `RecRoom.exe` —
   otherwise every launch opened a second debug console and left a stray process waiting on Unity.

2. **DNS host rewrite** (`src/hooks/dns_hook.c`). Detours `ws2_32!getaddrinfo`. A lookup for an exact
   `from` host in `redirector.json` (e.g. `ns.rec.net`) is resolved as its `to` host
   (`ns.recflare.net`) instead — we hand the rewritten name to real DNS, so the client reaches the
   target's *current* IP (survives dynamic IPs) rather than a pinned address. Surgical: only the
   configured hosts are affected. Necessary but **not sufficient** on its own — it changes only name
   resolution, leaving SNI and the `Host:` header saying `ns.rec.net`. Kept as a safety net under (3).

3. **HTTP host rewrite** (`src/unity/http_rewrite.c`) — the patch that actually moves traffic. Hooks
   the concrete static `BestHTTP.HTTPManager.SendRequest(HTTPRequest)`, reads
   `req.Uri.AbsoluteUri`, swaps the host through the same `redirector.json` pairs, and assigns a
   fresh `new Uri(...)` back before letting the real `SendRequest` run. The new host therefore
   carries end-to-end — URL, SNI and `Host:` — so the target can serve it as its own vhost with its
   own cert. Native equivalent of the managed build's `SendRequestPatch`. This is the one
   **call-through** hook, so it depends on the relocating trampoline in `src/memory/detour.c`.

4. **TLS pinning bypass** (`src/unity/ssl_patch.c`). Redirecting HTTPS means the handshake presents a
   cert the client would reject. Resolves the **concrete**
   `Org.BouncyCastle.Crypto.Tls.LegacyTlsAuthentication.NotifyServerCertificate` and detours its
   compiled body to a no-op that accepts unconditionally — the native equivalent of the managed
   build's `DisableTLSPinning` Harmony patch.

5. **Memory-integrity scan neutralizer** (`src/unity/memcheck_patch.c`). The client runs a background
   scan that hashes `GameAssembly.dll` code against baked-in hashes; the inline hooks above change
   that memory, so boot dies with *"Launch validation failed."* The scanner's name is obfuscated and
   rotates every build, so it is found **by signature** instead: the class in `Assembly-CSharp` that
   holds both a `Thread` and a `CancellationTokenSource` field. Its public instance 0-param non-void
   method is the scan entry point; we detour it to return an already-resolved promise (fetched from
   the promise type's static `Resolved` getter), so boot's await satisfies instantly. Started first
   among the il2cpp patches — the boot step that awaits the scan can fire early, and the reflection
   sweep needs a head start.

6. **EAC neutralizer** (`src/unity/eac_patch.c`). Two replace-only hooks on
   `RecRoom.AntiCheat.EACManager`: the readiness check (the sole static 0-param `bool`
   non-property-getter method — again resolved by signature, since the name rotates) is forced to
   `true`, because the real check needs EasyAntiCheat services that no longer exist; and
   `GenerateChallengeResponse(string)` (unobfuscated) returns `base64(challenge)`, with
   `base64("nothing")` for an empty/null challenge. Safe to patch only because (5) has already
   neutralized the hash check.

Everything from (2) on runs off one background thread spawned in `DllMain`; each il2cpp patch gets
its own thread, since they must wait on the runtime independently. `src/unity/module_watch.c` just
logs `GameAssembly.dll` / `UnityPlayer.dll` as they appear and then stops.

The `connect` and `gethostbyname` hooks are present but **intentionally not installed**: the
`connect` hook redirects *all* :443 traffic (would break Photon/CDN/telemetry), and `getaddrinfo`
already covers the il2cpp DNS path.

### Resolving obfuscated targets

Rec Room obfuscates its own type/method names and they rotate every build, so nothing here
hard-codes one. Framework names (`SendRequest`, `get_Uri`, `NotifyServerCertificate`,
`GenerateChallengeResponse`, `EACManager`) are stable and resolved literally; the anti-cheat internals
are resolved by **shape** — field types, method signature, return type — through the il2cpp
reflection API at runtime. Every candidate is logged, and an ambiguous match logs a `WARNING` rather
than silently guessing.

## Build

Requires VS 2022 (C toolchain) + CMake + Ninja (both ship with VS). **Must build x64** — a 32-bit
DLL silently fails to load. Import the amd64 VC environment first:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Output: `build\version.dll` — a single self-contained proxy (it loads the real system `version.dll`
at runtime, so there is nothing else to ship).

One-step deploy into the game folder (close Rec Room first — the DLL is locked while it runs):

```powershell
cmake -S . -B build -G Ninja -DGAME_DIR="C:\Games\recflare-client-unstable"
cmake --build build
```

## Install (manual)

1. Copy `build\version.dll` into the Rec Room install root (next to `RecRoom.exe`). If BepInEx's
   `version.dll` is there, replace it (this build does not use BepInEx).
2. Copy `redirector.json.example` to `redirector.json` there and set the `rewrite` pairs
   (`{ "from": "ns.rec.net", "to": "ns.recflare.net" }`). The same pairs drive both the DNS and the
   HTTP rewrite. Matching is exact — add one entry per host. Parsed by a flat key scan, not a real
   JSON parser, so keep it flat: one object per rewrite.
3. Launch. A console window opens; logs also go to `redirector_<pid>.log` beside `RecRoom.exe`.

A healthy run logs all of these (each patch runs on its own thread, so they interleave; `[MEMCHECK]`
lands last — its reflection sweep takes a moment):

```
[STATUS] DNS REDIRECT ACTIVE
[SSL]     TLS pinning bypassed (NotifyServerCertificate -> accept-all)
[EAC]     readiness check forced true
[EAC]     GenerateChallengeResponse -> base64(challenge)
[HTTP]    host rewrite installed on SendRequest
[MEMCHECK] native memory integrity scan skipped (scan-start -> resolved promise)
[HTTP]    https://ns.rec.net/ -> https://ns.recflare.net/          (one per request)
```

The per-request `[HTTP] ... -> ...` lines are the proof traffic is actually moving; everything above
them only says the hooks installed. `[DETOUR] ... refusing hook` means the detour engine wouldn't
touch that prologue (see below) and that patch is **not** active.

## Known limitations / open items

- **Obfuscated targets are matched by shape, not name.** A Rec Room build that changes the *structure*
  of the scanner class or the EAC readiness method — not just its name — will break that patch. The
  logs list every candidate considered, and warn when more than one matched, so a drift shows up as a
  `WARNING` or a "not identified" line rather than a silent misfire. Watch for `[MEMCHECK] scanner
  candidate` lines: more than one means the field-signature match is no longer unique.
- **The detour engine's length decoder is minimal.** It relocates rip-relative `disp32` and `rel32`
  branches into a trampoline allocated within ±2 GB, but bails on two-byte (`0F`) opcodes, `rel8`
  branches, and anything it doesn't model — and `InstallDetour` then **refuses the hook** rather than
  corrupt code. This only constrains call-through hooks (currently just `SendRequest`); replace-only
  hooks take a blind 14-byte overwrite, which is safe because they jump away and never execute the
  torn tail.
- **Nothing is undone on unload.** The detours stay installed for the life of the process; the saved
  original bytes are kept but never restored.
- **The anti-cheat may catch up.** The memory-integrity scan is neutralized at its managed entry
  point, not at the native scanner itself — a build that calls the scan from somewhere else, or adds a
  second check, would reject the client again.
