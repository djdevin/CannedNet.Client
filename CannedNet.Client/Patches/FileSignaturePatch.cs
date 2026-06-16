using HarmonyLib;

namespace CannedNet.Client.Patches;

// Rec Room validates game asset files against a signed manifest (obfuscated type JAPJPGNBMNM).
// When a file's signature doesn't match, it builds a *failure* result (nested type AOFCCEACNNA)
// via the factory PNEAHABDBHH(Exception) — the exception being JAPJPGNBMNM.HOOLEAJINMJ, whose
// message is "Signatures don't match!". Our BepInEx/mod presence perturbs a file enough to fail
// this check, so we convert any failure result into the parameterless success result
// JGIHNLEFJEL(), neutralizing the file-signature check.
//
// Both the type and method names are obfuscated and change between game builds (like EACManager's
// methods). If the build updates, re-find them by decompiling JAPJPGNBMNM with ilspycmd: AOFCCEACNNA
// is the result type, JGIHNLEFJEL() is its parameterless (success) factory, and PNEAHABDBHH(Exception)
// is the failure factory.
[HarmonyPatch(typeof(global::JAPJPGNBMNM.AOFCCEACNNA), "PNEAHABDBHH")]
public class FileSignatureCheckPatch
{
    private static void Postfix(ref global::JAPJPGNBMNM.AOFCCEACNNA __result)
    {
        // Doesn't seem required, maybe with EAC enabled?
        // It does throow this:
        // [Error  :     Unity] [08:47:53] [3139] [103.4982] [Error] [Error] File check failed JAPJPGNBMNM+HOOLEAJINMJ: Error validating file sharedassets74.assets: Signatures don't match!
        // That gets reported to playerreporting but of course we don't implement that.
        __result = global::JAPJPGNBMNM.AOFCCEACNNA.JGIHNLEFJEL();

        if (Plugin.Debug.Value)
            Plugin.Log.LogInfo("[FileSig] would have converted file-check failure result -> success");
    }
}
