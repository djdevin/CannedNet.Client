using HarmonyLib;
using RecRoom.AntiCheat;
using System.Text;
using Il2CppSystem;

namespace CannedNet.Client.Patches;

[HarmonyPatch]
public static class EACPatches
{
    [HarmonyPrefix]
    [HarmonyPatch(typeof(EACManager), "FJLMLEPOKGE")]
    private static bool IsReadyPatch(ref bool __result)
    {
        __result = true;
        return false;
    }

    [HarmonyPrefix]
    [HarmonyPatch(typeof(EACManager), "GenerateChallengeResponse")]
    private static bool GenerateChallengeResponsePatch(string __00, ref string __result)
    {
        if (!string.IsNullOrEmpty(__00))
            __result = Convert.ToBase64String(Encoding.UTF8.GetBytes(__00));
        else
            __result = Convert.ToBase64String(Encoding.UTF8.GetBytes("i hate this"));
        return false;
    }
}