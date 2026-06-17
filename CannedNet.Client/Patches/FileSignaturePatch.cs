using HarmonyLib;

namespace CannedNet.Client.Patches;

/**
    [Error  :     Unity] [08:47:53] [3139] [103.4982] [Error] [Error] File check failed JAPJPGNBMNM+HOOLEAJINMJ:
    Error validating file sharedassets74.assets: Signatures don't match!

    Rec Room validates game asset files against a signed manifest. You can find this file in each release
    at RecRoom_Data/verification.sig. The server has to deliver it at cdn.rec.net/sigs/[GUID], then
    is reported to playerreporting/v1/hile which probably ran reputation checks or something.
    even though it had no effect. We are probably modifying something in sharedassets74.assets and that's
    why the check fails.

    The rest of the documetation here is for Claude:
    When a file's signature doesn't match, it builds a *failure* result (nested type AOFCCEACNNA)
    via the factory PNEAHABDBHH(Exception) — the exception being JAPJPGNBMNM.HOOLEAJINMJ, whose
    message is "Signatures don't match!". Our BepInEx/mod presence perturbs a file enough to fail
    this check, so we convert any failure result into the parameterless success result
    JGIHNLEFJEL(), neutralizing the file-signature check.

    Both the type and method names are obfuscated and change between game builds (like EACManager's
    methods). If the build updates, re-find them by decompiling JAPJPGNBMNM with ilspycmd: AOFCCEACNNA
    is the result type, JGIHNLEFJEL() is its parameterless (success) factory, and PNEAHABDBHH(Exception)
    is the failure factory.
*/
[HarmonyPatch(typeof(global::JAPJPGNBMNM.AOFCCEACNNA), "PNEAHABDBHH")]
public class FileSignatureCheckPatch
{
    private static void Postfix(ref global::JAPJPGNBMNM.AOFCCEACNNA __result)
    {
        // Disabled for now. Doesn't seem to have any effect.
        //__result = global::JAPJPGNBMNM.AOFCCEACNNA.JGIHNLEFJEL();

        if (Plugin.Debug.Value)
            Plugin.Log.LogInfo("[FileSig] would have converted a file-check failure result -> success");
    }
}
