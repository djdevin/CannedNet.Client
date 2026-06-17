using HarmonyLib;
using Org.BouncyCastle.Crypto.Tls;

namespace CannedNet.Client.Patches;

/**
    Disable TLS checks. Even though the server is fully HTTPS with valid certificates, this still seems to fail. Rec Room might
    be pinning certificates.
*/
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
