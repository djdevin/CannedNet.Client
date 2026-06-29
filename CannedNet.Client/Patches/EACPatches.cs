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
    private static bool GenerateChallengeResponsePatch(string PGCINMIEBJP, ref string __result)
    {
        if (!string.IsNullOrEmpty(PGCINMIEBJP))
            __result = Convert.ToBase64String(Encoding.UTF8.GetBytes(PGCINMIEBJP));
        else
            __result = Convert.ToBase64String(Encoding.UTF8.GetBytes("i hate this"));
        return false;
    }
}