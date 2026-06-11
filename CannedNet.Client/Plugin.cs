using System;
using System.Collections;
using System.Text.Json;
using BepInEx;
using BepInEx.Configuration;
using BepInEx.Logging;
using BepInEx.Unity.IL2CPP;
using BepInEx.Unity.IL2CPP.Utils.Collections;
using HarmonyLib;
using UnityEngine;
using UnityEngine.Events;
using UnityEngine.SceneManagement;
using UnityEngine.Networking;

namespace CannedNet.Client;

[BepInPlugin("lapis.cannednet.client", "CannedNet Client", "1.0.0")]
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

    public override void Load()
    {
        Log = base.Log;
        
        AppIdRT = Config.Bind("Photon", "App Id Realtime", "", "Photon Realtime App ID");
        AppIdVoice = Config.Bind("Photon", "App Id Voice", "", "Photon Voice App ID");
        AppIdChat = Config.Bind("Photon", "App Id Chat", "", "Photon Chat App ID");
        EnableAdvancedSettings = Config.Bind("Advanced", "Enabled Advanced Settings", false, "Allows other fields below in the advanced section to be modified.");
        PhotonHostname = Config.Bind("Advanced", "Photon NameServer", "", "Custom Photon NameServer");
        PhotonPort = Config.Bind("Advanced", "Photon NameServer Port", 0, "Custom Photon NameServer Port (if 0, it will be default)");
        ServerHostname = Config.Bind("Server", "RecNet NameServer Host", "https://ns.lapis.codes", "Host for the RecNet NameServer.");
        Debug = Config.Bind("Advanced", "Debug", false, "Show debug logs (HTTP tracing, etc. WARNING: will include sensitive information such as passwords and auth tokens in the logs, be careful when sharing them!)");

        Harmony.CreateAndPatchAll(typeof(Plugin).Assembly);
        
        SceneManager.sceneLoaded += (Action<Scene, LoadSceneMode>)OnSceneLoaded;
    }

    private void OnSceneLoaded(Scene scene, LoadSceneMode mode)
    {
        var cheatMgr = GameObject.Find("GameRoot/(Startup)(Clone)/Core Systems/[CheatManager]");
        if (cheatMgr != null)
        {
            GameObject.Destroy(cheatMgr);
            Log.LogInfo("cheatmanager destroyed");
        }
    }
}

