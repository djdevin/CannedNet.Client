using HarmonyLib;

namespace RecNetPlugin.Patches;

// CheatManager is Rec Room's DUID service (it implements PGECJHKNIEN, and also exposes WriteDUIDs /
// ClearDUIDs). CheckForDUIDMismatch(out string) returns true when the machine's stored device id
// differs from the freshly-derived one; a true result sends the client down the device-id migration
// path, which POSTs PlayerReporting/v1/deviceId and then stalls on Create Account without ever
// reaching the create_account OAuth call.
//
// Patch the concrete CheatManager method, NOT PGECJHKNIEN: the interface methods are abstract, so
// Harmony patches them without error but the game dispatches to the implementation and the patch
// never runs.
[HarmonyPatch]
public static class DUIDMismatchPatch
{
    // Stand-in stored id used to fake a mismatch. Any value that differs from the real derived id
    // works; this is the truncated one seen in the field, kept so simulated logs look like real ones.
    private const string SimulatedStoredDeviceId = "491e8b9";

    [HarmonyPrefix]
    [HarmonyPatch(typeof(CheatManager), "CheckForDUIDMismatch")]
    private static bool Prefix(ref string ALOMDLLNIMD, ref bool __result)
    {
        if (Plugin.SimulateDUIDMismatch.Value)
        {
            ALOMDLLNIMD = SimulatedStoredDeviceId;
            __result = true;
            Plugin.Log.LogWarning($"[DUID] simulating mismatch, stored id = {SimulatedStoredDeviceId}");
            return false;
        }

        ALOMDLLNIMD = string.Empty;
        __result = false;
        Plugin.Log.LogInfo("[DUID] mismatch check forced to false");
        return false;
    }
}
