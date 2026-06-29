using HarmonyLib;
using Org.BouncyCastle.Crypto.Tls;

namespace CannedNet.Client.Patches;

public class FuckOffTLS
{
    [HarmonyPatch(typeof(LegacyTlsAuthentication), "NotifyServerCertificate")]
    public class TlsPatch
    {
        private static bool Prefix()
        {
            return false;
        }
    }
}