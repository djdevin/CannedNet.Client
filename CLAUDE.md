# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This is the **native (C/Win32) redirector** that points the Rec Room client at a self-hosted server
**without any managed mod loader**. It replaces the sibling `../recnet-patcher` project (a BepInEx/
MelonLoader Harmony plugin) — both loaders fail on current Rec Room builds (BepInEx crashes in
`il2cpp_init`; the loader trips the anti-cheat memory-integrity scan). This build is loaded as a
`version.dll` proxy and hooks Winsock + il2cpp methods directly in native code. Read `README.md` for
the user-facing overview; this file is the stuff you only learn by getting burned.

## Build & deploy

Rec Room / `GameAssembly.dll` is **64-bit — you must build x64**. A 32-bit DLL silently fails to load.
The default VS dev shell is x86, and the PowerShell tool **does not persist env vars between calls**,
so the amd64 env import and the cmake/build must run in the **same** call, else you get an x86 DLL:

```powershell
$vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
cmd /c "`"$vcvars`" amd64 >nul 2>&1 && set" | ForEach-Object { if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "Env:$($matches[1])" -Value $matches[2] } }
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release   # add -DGAME_DIR="C:\Games\recflare-client-unstable" to deploy
cmake --build build
```

- **Verify arch** from the PE header after building: machine word at `(int32 @0x3C)+4` must be **0x8664**,
  not 0x014C. `cmake` refuses to configure a non-64-bit toolchain (guard in `CMakeLists.txt`).
- Toolchain: VS 2022 Community; `cmake`/`ninja` ship with it. Installed Windows SDK is **10.0.19041.0**;
  the VS-generator MSBuild probe can't find it without the VC env — another reason to use Ninja inside
  the imported amd64 env.
- Build output is **`build\version.dll`** (`OUTPUT_NAME version`, `PREFIX ""`) and that is the *only*
  artifact — it is self-contained. It used to ship alongside a `version_orig.dll` (a copy of the system
  DLL) that its exports statically forwarded to; that dependency was removed in f3eb296 in favour of
  runtime forwarding, so **do not** re-add a copy step for it. `-DGAME_DIR=...` copies `version.dll`
  into the game folder. **The copy fails while Rec Room is running** (DLL locked) — close the game first.

## Architecture

`DllMain` (`src/dllmain.c`) spawns one background thread — `HookThread` in
`src/hooks/hook_manager.c` — which gates on `IsGameProcess()`, installs the ws2_32 hooks inline, then
fans each il2cpp patch out onto **its own thread**, since they each wait independently on the runtime
coming up. Order matters only for the memcheck patch (started first, see 5). The pipeline:

1. **Loader vector — `version.dll` proxy** (`src/proxy/version_proxy.c`). `RecRoom.exe` imports
   `VERSION.dll` by name, and the loader searches the app dir before System32, so our `version.dll`
   loads very early (before `UnityPlayer.dll`). All 17 real exports are satisfied by local `my_*`
   wrappers, aliased to the real names via `#pragma comment(linker, "/export:NAME=my_NAME")` (aliases,
   **not** PE forwarders — no dot in the target). Each wrapper lazily `LoadLibraryW`s the genuine
   `%SYSTEM32%\version.dll` **by absolute path** (so the app-dir search can't loop back into us) and
   calls through. `DllMain` starts the hook thread. To retarget at `winhttp.dll` instead, swap this
   file's export list for winhttp's.

2. **DNS host rewrite** (`src/hooks/dns_hook.c`, detours `ws2_32!getaddrinfo`). On an **exact-match**
   lookup it swaps the hostname (`ns.rec.net` → `ns.recflare.net`) and delegates to the real
   `getaddrinfo`, so the client reaches the target's *current* IP. This alone is **not sufficient** —
   it only changes DNS resolution; SNI and the HTTP `Host:` header still say `ns.rec.net`. Kept as a
   safety net.

3. **HTTP host rewrite** (`src/unity/http_rewrite.c`) — the real fix. The alternate backend
   (`ns.recflare.net`) serves its own vhost/cert, so requests must carry that host in URL + SNI + Host.
   This replicates the managed `SendRequestPatch`: it waits for the il2cpp runtime, resolves the
   concrete static `BestHTTP.HTTPManager.SendRequest(HTTPRequest)`, reads `req.get_Uri().get_AbsoluteUri()`,
   swaps the host, and `req.set_Uri(new System.Uri(...))` before forwarding. **This is a call-through
   hook** (must run the original) so it depends on the trampoline in `detour.c`.

4. **TLS pinning bypass** (`src/unity/ssl_patch.c`). Redirecting to a mismatched cert fails the
   handshake; this resolves the concrete `Org.BouncyCastle.Crypto.Tls.LegacyTlsAuthentication`
   `.NotifyServerCertificate` and detours it to an accept-all no-op. **Replace-only** hook (never calls
   the original).

5. **Memory-integrity scan neutralizer** (`src/unity/memcheck_patch.c`) — **the reason 3/4/6 are
   possible at all.** A background scan hashes `GameAssembly.dll` code against baked-in hashes; our
   inline patches change that memory, so boot dies *"Launch validation failed. Is Rec Room installed
   correctly?"*. The scanner class is obfuscated and **rotates every build**, so it is matched by
   *shape*: the class in `Assembly-CSharp.dll` carrying both a `System.Threading.Thread` and a
   `CancellationTokenSource` field. Its public/instance/0-param/non-void method is the scan entry; its
   return type is the promise the boot step awaits. We detour that entry (replace-only) to return an
   already-resolved promise, obtained by `il2cpp_runtime_invoke` on the promise type's static
   special-name 0-param `Resolved` getter (found by sweeping every image for a getter returning that
   exact class, skipping `_k__BackingField`). The getter is test-invoked **before** committing the
   detour — if it returns null or throws we skip the hook rather than hand boot a null promise.
   `PatchMemoryIntegrityCheck` is started **first** among the il2cpp patches: the boot step that awaits
   the scan can fire early and the reflection sweep takes ~700 ms, so it needs the head start.

6. **EAC neutralizer** (`src/unity/eac_patch.c`). Two replace-only hooks on the literal
   `RecRoom.AntiCheat.EACManager` (namespace+class are *not* obfuscated; the methods are):
   - **Readiness → true.** The real check needs EasyAntiCheat services that no longer exist. Matched by
     shape: the sole static, 0-param, `bool`-returning, **non**-special-name method (excluding
     special-name is what keeps property getters out). Hook returns 1 — note the native signature is
     `(void *methodInfo)`, since a static il2cpp method still gets `MethodInfo*` in RCX.
   - **`GenerateChallengeResponse(string)` → `base64(challenge)`**, `base64("nothing")` for null/empty.
     Unobfuscated name, resolved directly. `g_gcr_static` is read from the method flags because it
     decides whether the string arg arrives in RCX or RDX — get that wrong and you base64 a `this`
     pointer.

   Both are only safe because 5 has already neutralized the hash check.

`src/core/` = logger + JSON-ish config + process info (incl. `IsGameProcess`). `src/utils/strings.c` = host match/rewrite.
`src/debug/` and `connect_hook.c` are logging stubs / the disabled connect hook. Config is
`redirector.json` next to `RecRoom.exe` (sample `.example`), parsed by a **flat key-scan, not real
JSON** — keep it flat, one object per rewrite.

## Hard-won gotchas (read before touching hooks)

1. **The detour engine has two modes; picking wrong corrupts code** (`src/memory/detour.c`).
   `InstallDetour(target, hook, backup, outTrampoline)`:
   - `outTrampoline != NULL` → **call-through**: it length-decodes the prologue (`decode`/`steal_len`),
     copies **whole instructions** (≥14 bytes) into a trampoline with relocation fixups
     (`RelocateInto`), and NOP-pads. Use when the hook calls the original (DNS, HTTP).
   - `outTrampoline == NULL` → **replace-only**: a blind 14-byte overwrite. Only safe when the hook
     never calls through (SSL), because we jump away immediately so a torn trailing instruction is never
     executed.
   The original crash bug was a *blind* 14-byte copy on a call-through target: `ws2_32!getaddrinfo`'s
   prologue has instruction boundaries at 3/7/11/**15**, so 14 bytes tore the 4th `mov` and the
   trampoline ran garbage → whichever thread called the original died. The symptom was subtle: the game
   booted (the first lookup runs on a Unity *background* thread that died silently) but the client's real
   API lookup later hit the same broken trampoline and its thread died before any request left the process.

2. **The length decoder relocates two cases and bails on the rest.** `decode()` classifies each
   instruction: `RK_RIPREL` (rip-relative disp32, `mod=00,rm=101`) and `RK_REL32` (`E8`/`E9`) are
   **relocated** — `AllocNear` places the trampoline within ±2 GB of the target so the rewritten
   displacements still fit in int32, and each fixup is range-checked. rip is computed from the *end of
   the whole instruction*, past any trailing immediate. `decode` returns 0 on a two-byte (`0x0F`)
   opcode or anything it doesn't model, and `rel8` branches are measured but flagged `RK_UNSUPPORTED`
   (they'd need a rel8→rel32 rewrite); in all those cases `InstallDetour` **refuses the hook** (logs
   it) rather than corrupt code. This is what unblocked the call-through hook on
   `HTTPManager.SendRequest`, whose prologue is the usual il2cpp class-init check `cmp byte [rip+disp],
   0` + `jne` — it now steals 16 bytes and relocates cleanly. ws2_32 stubs are position-independent and
   hook fine as-is (`getaddrinfo` steals 15).

3. **il2cpp method resolution.** Resolve types by literal namespace+name across all loaded assemblies
   (`il2cpp_domain_get_assemblies` → `il2cpp_assembly_get_image` → `il2cpp_class_from_name` — the last
   only searches the image you give it, so sweep). Get methods with `il2cpp_class_get_method_from_name`
   (argc counts declared params only). **There is no `il2cpp_method_get_pointer` export** — read the
   compiled entry from `MethodInfo` offset 0 (`methodPointer`, `*(void**)method`). Wait for
   `il2cpp_domain_get()` to be non-NULL (runtime init) before resolving, and `il2cpp_thread_attach` your
   native thread before any metadata call. Interop DLLs name the type `Il2CppSystem.Uri`, but the runtime
   metadata namespace is plain `System`/`Uri`.

4. **Framework names are stable; patch the concrete class.** `SendRequest`, `get_Uri`/`set_Uri`,
   `AbsoluteUri`, `NotifyServerCertificate`, `HTTPManager`, `LegacyTlsAuthentication` are unobfuscated and
   have survived build changes — this is *why* these are the hook points. As in the managed project, hook
   the **concrete** impl, never an il2cpp interface. Verify signatures with Mono.Cecil against the interop
   in `../recflare-client/BepInEx/interop` when they drift (see the sibling `../recnet-patcher/CLAUDE.md`
   for the Cecil load snippet; that project's interop has the same types).

5. **version.dll loads into multiple processes — log per-PID.** Our DLL loads into the game, the
   EasyAntiCheat launcher/bootstrap, and the crash handler. They previously shared `redirector.log` opened
   with `"w"` and truncated each other (the EAC process, stuck forever in `WaitForUnity` because
   `UnityPlayer.dll` never loads there, buried the game's diagnostics under module dumps). The logger now
   writes **`redirector_<pid>.log`**, and `WaitForUnity` is time-bounded. `HookThread` now returns
   immediately unless `IsGameProcess()` (`src/core/process.c`, basename == `RecRoom.exe`) — that check
   sits **before** `InitConsole`/`InitLogger`, because `AllocConsole` in the crash-handler process was
   opening a second debug window on every launch. So only `RecRoom.exe` writes a log at all now; if you
   need diagnostics from a sibling process, move the gate to wrap `InitConsole` alone.

6. **The connect hook is intentionally disabled.** `src/hooks/connect_hook.c` blindly redirects *all*
   :443 traffic (would break Photon/CDN/telemetry). `getaddrinfo` covers the il2cpp DNS path surgically.
   `gethostbyname` also has a latent self-recursion bug (calls `real_gethostbyname`, not a trampoline) if
   ever installed.

7. **Rec Room's own names are obfuscated and rotate every build — match by shape, never by name.**
   Gotcha 4's framework names are the exception; anything in `Assembly-CSharp` is an 11-char scramble
   (`NAEMGPMOPED`, `JMCKLNABHHJ`) that differs next build, so **never hard-code one you saw in a log**.
   The two patches that need such a target (5, 6) locate it through the il2cpp reflection API by
   structure instead — field types, static-ness, param count, return type, special-name flag. Rules
   that follow from getting this wrong:
   - **Log every candidate; warn on >1.** The *method* searches count matches and log
     `WARNING N candidates` when ambiguous (scan-start in 5, readiness in 6). The **scanner class**
     search in 5 does not — it logs each `[MEMCHECK] scanner candidate` and silently keeps the last.
     Real logs already show **two**, so that field signature is *not* unique and the patch is riding on
     ordering. It works today; treat it as the most fragile thing here, and read those lines before
     trusting a boot.
   - **Never fall back to "close enough".** Every resolver bails with a log line rather than hooking a
     guess — a wrong detour on a rotating target corrupts an unrelated method.
   - **Verify before committing an irreversible detour** where you can (5 test-invokes the `Resolved`
     getter first).

## Inspecting the game

- **Runtime**: the per-PID log is the source of truth. Our tags: `[STATUS] [HOOK] [DETOUR] [DNS ...]`
  `[REWRITE] [REDIRECT] [SSL] [HTTP] [MEMCHECK] [EAC]`. Success = `[HTTP] host rewrite installed on
  SendRequest` then `[HTTP] https://ns.rec.net/... -> https://ns.recflare.net/...` per request. A
  `[DETOUR] ... refusing hook` line means gotcha 2 — the decoder hit a prologue it won't relocate
  (`0x0F` opcode, `rel8` branch, or an unmodelled opcode), and **that patch is not active**.
- **Static il2cpp**: dump prologue bytes from `GameAssembly.dll` by converting the logged runtime `code=`
  address to an RVA (subtract the logged `GameAssembly.dll Base`) and mapping RVA→file offset via the PE
  section headers. Method/field signatures: Mono.Cecil over the interop DLLs (see gotcha 4).
- PowerShell here is Windows PowerShell 5.1 — no `?.`; use explicit `$x -eq $null`. Avoid `2>&1` on native
  exes.
