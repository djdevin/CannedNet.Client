using HarmonyLib;

namespace RecNetPlugin.Patches;

/**
 * This allows the global-metadata.dat to be different on the client
 * patched to allow a different modulus so we can sign images.
*/
[HarmonyPatch(typeof(JAPJPGNBMNM), "JOKECJKBJGD")]
public static class PromisePatch
{
    public static bool Prefix(out HPHDJAFFHCN<JAPJPGNBMNM.AOFCCEACNNA> __result)
    {
        var result = JAPJPGNBMNM.AOFCCEACNNA.JGIHNLEFJEL();
        var promise = HAAHJPGNIMD.NMOOLKAJDOC(result);
        __result = promise;
        return false;
    }
}
