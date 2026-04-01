# RecNet Plugin

A [BepInEx 6](https://github.com/BepInEx/BepInEx) (IL2CPP) plugin that points the Rec Room client at a self-hosted / private server.

It does this entirely client-side with [Harmony](https://harmony.pardeike.net/) patches — no game files are modified on disk (except global-metadata.dat - needed for image signatures). The plugin rewrites the RecNet name-server lookups, swaps in your own Photon credentials, and disables the client-side guards (EasyAntiCheat, TLS certificate pinning) that would otherwise reject a non-official server.

> ⚠️ This disables anti-cheat and certificate validation on the client. Use at your own risk.

## Safety

Using BepInEx plugins may cause anti-virus scanners or Windows Defender to pick it up as a threat.

If you don't trust the complied .DLL, you can build it yourself.

See https://github.com/djdevin/recnet-plugin#from-source

## What it does

| Patch | File | Effect |
| --- | --- | --- |
| Name-server redirect | `Patches/SendRequestPatch.cs` | Intercepts `BestHTTP` requests and rewrites the host `ns.rec.net` → your configured server. Also provides optional HTTP request/response logging for development. |
| Photon override | `Patches/PhotonPatches.cs` | Replaces the Realtime / Voice / Chat App IDs (and optionally the Photon name server + port) with your own. |
| EAC bypass | `Patches/EACPatches.cs` | Forces EasyAntiCheat "ready" and stubs the challenge-response so the client connects without the official anti-cheat. |
| TLS bypass | `Patches/FuckOffTLS.cs` | Skips server-certificate validation so a custom server's cert is accepted. |
| Promise stub | `Patches/PromisePatch.cs` | Allows custom global-metadata.dat files without the game crashing. |
| CheatManager handling | `Plugin.cs` | Deactivates the in-game `CheatManager` (which would otherwise boot you from rooms) while keeping it resolvable for account creation / login. |

## Requirements

- A Rec Room install set up with **BepInEx 6 (IL2CPP, bleeding-edge)**, launched at least once so the IL2CPP interop assemblies have been generated under `BepInEx/interop/`.
- **.NET 6 SDK** to build the plugin.
- Your own server endpoints: a RecNet name server, and [Photon](https://www.photonengine.com) app keys.

_Looking for a custom RecNet server?_ Try https://github.com/djdevin/recflare

## Installing

1. Download the game using https://github.com/SteamRE/DepotDownloader. The manifest ID is `7859140924515540835`.  
Example: `depotdownloader -app 471710 -depot 471711 -manifest 7859140924515540835`
**You must use this specific version.**
2. Install BepInEx to the game. See https://docs.bepinex.dev/articles/user_guide/installation/index.html. **Note that you must use version 6!**

### From release

1. Download a release from [/releases](/releases)
2. Drop the `.dll` file into `BepInEx/plugins/`

### From source

The project references the game's interop DLLs, so the build needs to know where your Rec Room install lives. Set `GamePath` using any one of:

1. **A local props file** (recommended):
   ```sh
   cp GamePath.props.example GamePath.props
   ```
   then edit `GamePath` in `GamePath.props` to point at your Rec Room install root. This file is local-only and stays out of the repo.

2. **An environment variable:**
   ```sh
   set RECROOM_PATH=C:\Path\To\RecRoom        # cmd
   $env:RECROOM_PATH = "C:\Path\To\RecRoom"   # PowerShell
   ```

3. **On the command line:**
   ```sh
   dotnet build -p:GamePath="C:\Path\To\RecRoom"
   ```

Then build:

```sh
dotnet build
```

The build validates that `GamePath` is set and that `$(GamePath)\BepInEx\interop` exists, and fails with a clear message otherwise.

A post-build step (the `DeployPlugin` target in the `.csproj`) automatically copies the built `RecNetPatcher.dll` into your Rec Room install's `BepInEx/plugins/` folder after every build. Since `GamePath` already points at your install, you don't need to copy anything by hand — just `dotnet build` and launch the game.

If you need the DLL elsewhere, it's also left in `bin/Debug/net6.0/`.

## Configuration

Start the game for the first time. In `BepInEx` you should now see a `config` folder. If not, verify BepInEx installation and version.

Inside `config`, edit the `net.rec.plugin.cfg` file and update as needed:

**[Server]**
- `RecNet NameServer Host` — base URL of your RecNet name server (like `https://ns.rec.net`).

**[Photon]**
- `App Id Realtime` — Photon Realtime App ID.
- `App Id Voice` — Photon Voice App ID.
- `App Id Chat` — Photon Chat App ID.

**[Advanced]**
- `Enabled Advanced Settings` — must be `true` to apply the custom Photon name server / port below.
- `Photon NameServer` — custom Photon name server host.
- `Photon NameServer Port` — custom port (`0` uses the default, `4533`).
- `Debug` — verbose HTTP request/response logging (only needed for development)
  > ⚠️ Debug logs include **sensitive data** (passwords, auth tokens). Be careful when sharing them.

## Project layout

| Path | Purpose |
| --- | --- |
| `Plugin.cs` | Plugin entry point, config bindings, Harmony bootstrap |
| `Patches/` | Harmony patches (HTTP, EAC, TLS, Photon) |
| `RecNetPlugin.csproj` | Build config + interop references (driven by `GamePath`), and the `DeployPlugin` post-build copy |
| `GamePath.props.example` | Template for your local `GamePath.props` |

## FAQ

**Can I use this for my own Rec Room server?**

Yes. That's the point.

## Credits

Based on https://github.com/CannedNet/CannedNet.Client

## License

[MIT](LICENSE)
