using HarmonyLib;

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
