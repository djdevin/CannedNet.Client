using System;
using System.Reflection;
using ExitGames.Client.Photon;
using HarmonyLib;
using Photon.Realtime;

namespace CannedNet.Client.Patches;

[HarmonyPatch(typeof(GPFPFDBGCEK), "AMOHMPKKGHL")]
public class PhotonPatches
{
    [HarmonyPostfix]
    private static void Postfix(ref AppSettings __result)
    {
        Plugin.Log.LogInfo("okay im patching now");

        if (__result != null)
        {
            __result.AppIdRealtime = Plugin.AppIdRT.Value;
            __result.AppIdVoice = Plugin.AppIdVoice.Value;
            __result.AppIdChat = Plugin.AppIdChat.Value;
            __result.FixedRegion = "us";
            __result.UseNameServer = true;
            __result.Protocol = ConnectionProtocol.Udp;

            if (Plugin.EnableAdvancedSettings.Value)
            {
                __result.Server = Plugin.PhotonHostname.Value;
                __result.Port = Plugin.PhotonPort.Value == 0
                    ? 4533
                    : Plugin.PhotonPort.Value;
            }
        }
    }
}
