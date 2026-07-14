using System;
using BepInEx;
using BepInEx.Configuration;
using BepInEx.Logging;
using BepInEx.Unity.IL2CPP;
using HarmonyLib;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace RecNetPlugin;

[BepInPlugin("net.rec.plugin", "RecNet Plugin", "1.0.0")]
public class Plugin : BasePlugin
{
    internal static new ManualLogSource Log;

    public static ConfigEntry<string> AppIdRT { get; private set; }
    public static ConfigEntry<string> AppIdVoice { get; private set; }
    public static ConfigEntry<string> AppIdChat { get; private set; }
    public static ConfigEntry<string> ServerHostname { get; private set; }
    public static ConfigEntry<bool> EnableAdvancedSettings { get; private set; }
    public static ConfigEntry<string> PhotonHostname { get; private set; }
    public static ConfigEntry<int> PhotonPort { get; private set; }
    public static ConfigEntry<bool> Debug { get; private set; }
    public static ConfigEntry<bool> SimulateDUIDMismatch { get; private set; }
    public static ConfigEntry<bool> SuppressDUIDMismatch { get; private set; }
    public static ConfigEntry<bool> CorruptStoredDUID { get; private set; }
    public static ConfigEntry<bool> RestoreStoredDUID { get; private set; }
    public static ConfigEntry<string> DeviceIdResponseOverride { get; private set; }
    public static ConfigEntry<int> DeviceIdResponseStatus { get; private set; }

    private static bool _corruptDone;

    public override void Load()
    {
        Log = base.Log;

        AppIdRT = Config.Bind("Photon", "App Id Realtime", "", "Photon Realtime App ID");
        AppIdVoice = Config.Bind("Photon", "App Id Voice", "", "Photon Voice App ID");
        AppIdChat = Config.Bind("Photon", "App Id Chat", "", "Photon Chat App ID");
        EnableAdvancedSettings = Config.Bind("Advanced", "Enabled Advanced Settings", false, "Allows other fields below in the advanced section to be modified.");
        PhotonHostname = Config.Bind("Advanced", "Photon NameServer", "", "Custom Photon NameServer");
        PhotonPort = Config.Bind("Advanced", "Photon NameServer Port", 0, "Custom Photon NameServer Port (if 0, it will be default)");
        ServerHostname = Config.Bind("Server", "RecNet NameServer Host", "https://ns.rec.net", "Host for the RecNet NameServer.");
        Debug = Config.Bind("Advanced", "Debug", false, "Show debug logs (HTTP tracing, etc. WARNING: will include sensitive information such as passwords and auth tokens in the logs, be careful when sharing them!)");
        SimulateDUIDMismatch = Config.Bind("Advanced", "Simulate DUID Mismatch", false, "Force CheckForDUIDMismatch to return TRUE (fakes the comparison only). Reproduces the hang path but does not corrupt any stored value. Leave false for normal play.");
        SuppressDUIDMismatch = Config.Bind("Advanced", "Suppress DUID Mismatch", true, "Force CheckForDUIDMismatch to return FALSE (the workaround fix, ON by default): the client never migrates and never takes the Create Account hang path. No-op on healthy machines (the real check returns false anyway); on mismatched machines it skips the hang. Set false only to observe the real mismatch behavior for debugging.");
        CorruptStoredDUID = Config.Bind("Advanced", "Corrupt Stored DUID", false, "ONE-SHOT TEST: on next launch, write a truncated device id into the DUID pref via the game's own WriteDUIDs, producing a genuinely corrupt STORED value (real current id) — exactly the friend's condition. After it logs '[CORRUPT] wrote', set this back to false and relaunch to drive the real mismatch path. Use 'Restore Stored DUID' to undo.");
        RestoreStoredDUID = Config.Bind("Advanced", "Restore Stored DUID", false, "ONE-SHOT UNDO: on next launch, call WriteDUIDs with the real device id, overwriting any corrupt stored value with a good one. Set back to false after it logs '[CORRUPT] restored'.");
        DeviceIdResponseOverride = Config.Bind("Advanced", "DeviceId Response Override", "", "Replace the body of the PlayerReporting/v1/deviceId response with this text, to test what shape the client will accept. Empty = leave the server's response alone.");
        DeviceIdResponseStatus = Config.Bind("Advanced", "DeviceId Response Status", 200, "HTTP status to force on the PlayerReporting/v1/deviceId response. Only applies when the override body is set.");

        Harmony.CreateAndPatchAll(typeof(Plugin).Assembly);

        SceneManager.sceneLoaded += (Action<Scene, LoadSceneMode>)OnSceneLoaded;
    }

    private void OnSceneLoaded(Scene scene, LoadSceneMode mode)
    {
        // CheatManager boots us out of rooms when it runs, but it's ALSO the DUID service the DI
        // container resolves for account creation / login (destroying it removes that service).
        // So instead of destroying it, *deactivate* the GameObject: it stops running (no Update /
        // coroutines, so no boot) while the component still exists, so the DI container can still
        // resolve PGECJHKNIEN and call its DUID methods. It's recreated per scene, so deactivate
        // each freshly-spawned (active) instance on every load. (GameObject.Find only returns active
        // objects, so once deactivated it isn't found again.)
        var cheatMgr = GameObject.Find("GameRoot/(Startup)(Clone)/Core Systems/[CheatManager]");
        if (cheatMgr == null)
            return;

        // One-shot corruption for testing: must run while the component is still active (before we
        // deactivate it below), because it calls the live CheatManager.WriteDUIDs().
        if (CorruptStoredDUID.Value && !_corruptDone)
            _corruptDone = Patches.CorruptDUIDPatch.CorruptStored(cheatMgr);
        else if (RestoreStoredDUID.Value && !_corruptDone)
            _corruptDone = Patches.CorruptDUIDPatch.RestoreStored(cheatMgr);

        cheatMgr.SetActive(false);
        Log.LogInfo("cheatmanager deactivated");
    }
}
