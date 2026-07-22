using System;
using HarmonyLib;
using Il2CppInterop.Runtime.InteropTypes.Arrays;
using Il2CppSystem.Security.Cryptography;
using Convert = Il2CppSystem.Convert;

namespace RecNetPlugin.Patches;

// Image signing: the client verifies images against an RSA public key whose modulus is a string
// literal in global-metadata.dat. Patching that literal is fragile, so we intervene at the framework
// level instead, between the literal and the verify.
//
// The stored value is 256 bytes once base64-decoded and does NOT start with 0x30, so it is a RAW
// 2048-bit modulus, not a DER/SPKI blob. The client therefore has to base64-decode it and hand-build
// an RSAParameters { Modulus, Exponent }. Both of those steps are plain framework calls with
// unobfuscated names, which is why hooking here survives game rebuilds (unlike the obfuscated
// PromisePatch this replaces).
//
// Two knobs, see [Signing] in the .cfg:
//   Disable Signature Verification -> THE FIX (default true). Forces the RSA verify to succeed, so
//                                    the modulus never has to match and unsigned images load. This
//                                    self-hosted setup does not use image signing.
//   Signing Modulus Override      -> secondary: swap in your own modulus and keep real verification,
//                                    for a deployment that DOES want signed images. Ignored (well,
//                                    redundant) while the verify is disabled.
//
// Both are belt-and-braces: we swap at Convert.FromBase64String (catches the value regardless of
// which crypto stack consumes it) AND at ImportParameters (catches it if the client uses some other
// base64 decoder). Whichever fires first wins; the second sees the already-swapped value and no-ops.
//
// If the log never shows "[SIG] stock modulus seen", the client is not using mscorlib RSA at all —
// the fallback is BestHTTP.SecureProtocol.Org.BouncyCastle, where the equivalent hooks are
// RsaKeyParameters..ctor(bool, BigInteger, BigInteger) and the concrete RsaDigestSigner/PssSigner
// .VerifySignature (NOT the ISigner "interface", which is abstract and never dispatches).
[HarmonyPatch]
public static class ImageSigningPatch
{
    // The stock 2048-bit public modulus baked into global-metadata.dat (base64, 344 chars).
    private const string StockModulusBase64 =
        "X07yXkxaaLcZ1wVXfkWjgFkkqdoLhDFm0GPODsF+Q47pSUlbLvtXGqStnyEJEIrQmgDiicAvCdGRq4lovr2l5sIP" +
        "MaoyizsbVHBdwLUrCsji0RvSBnmvN+8KqQ8STnB4DP4pAsPilfD35def4WuX/xMCXB5+hQUVhv27HPV8Dj9XzHuJ" +
        "AijIM9UwDZmvUcECyiO4wv+TaZi2+ELBtaLCQR8Gm1ZPeDEwP62Ch6MJy0jx5pkvvD0KdF9Wye+3/Wx31Zn/Trdo" +
        "9HL4sGFWPDM9H9kQhZd5wkTHuxpwGIIhlzIwvY2/pBGdZKP6fi1D2jROEmVkBDyhmYY9nO+s3/bndQ==";

    private const int ModulusBytes = 256;

    private static byte[] _stockModulus;
    private static byte[] _override;
    private static bool _overrideResolved;
    private static bool _loggedSeen;
    private static bool _loggedForced;

    private static byte[] Stock => _stockModulus ??= System.Convert.FromBase64String(StockModulusBase64);

    // Decoded lazily and cached, so a malformed config value is reported once instead of per call.
    private static byte[] Override
    {
        get
        {
            if (_overrideResolved)
                return _override;
            _overrideResolved = true;

            var raw = Plugin.SigningModulusOverride.Value;
            if (string.IsNullOrWhiteSpace(raw))
                return _override = null;

            try
            {
                var bytes = System.Convert.FromBase64String(raw.Trim());
                if (bytes.Length != ModulusBytes)
                {
                    Plugin.Log.LogError(
                        $"[SIG] 'Signing Modulus Override' decoded to {bytes.Length} bytes, expected {ModulusBytes} " +
                        "(a raw 2048-bit modulus). Ignoring it. Note this must be the bare modulus, NOT a PEM/DER key.");
                    return _override = null;
                }

                Plugin.Log.LogWarning("[SIG] signing modulus override active");
                return _override = bytes;
            }
            catch (FormatException)
            {
                Plugin.Log.LogError("[SIG] 'Signing Modulus Override' is not valid base64. Ignoring it.");
                return _override = null;
            }
        }
    }

    private static bool IsStock(Il2CppStructArray<byte> value)
    {
        if (value == null || value.Length != ModulusBytes)
            return false;

        var stock = Stock;
        for (var i = 0; i < ModulusBytes; i++)
            if (value[i] != stock[i])
                return false;

        return true;
    }

    private static void NoteSeen(string where)
    {
        if (_loggedSeen)
            return;
        _loggedSeen = true;
        Plugin.Log.LogWarning($"[SIG] stock modulus seen at {where}");
    }

    // Choke point 1: the base64 decode of the literal. Guarded by a length check first, because this
    // runs for every base64 decode in the game.
    [HarmonyPrefix]
    [HarmonyPatch(typeof(Convert), nameof(Convert.FromBase64String))]
    private static bool FromBase64StringPrefix(string __0, ref Il2CppStructArray<byte> __result)
    {
        if (__0 == null || __0.Length != StockModulusBase64.Length || __0 != StockModulusBase64)
            return true;

        NoteSeen("Convert.FromBase64String");

        var replacement = Override;
        if (replacement == null)
            return true;

        var arr = new Il2CppStructArray<byte>(ModulusBytes);
        for (var i = 0; i < ModulusBytes; i++)
            arr[i] = replacement[i];

        __result = arr;
        return false;
    }

    // Choke point 2: the key import. Mutates the modulus in place — both are 2048-bit, so the array
    // is already the right size and no reallocation is needed.
    [HarmonyPrefix]
    [HarmonyPatch(typeof(RSACryptoServiceProvider), nameof(RSACryptoServiceProvider.ImportParameters))]
    private static void ImportParametersPrefix(RSAParameters __0)
    {
        var modulus = __0?.Modulus;
        if (!IsStock(modulus))
            return;

        NoteSeen("RSACryptoServiceProvider.ImportParameters");

        var replacement = Override;
        if (replacement == null)
            return;

        for (var i = 0; i < ModulusBytes; i++)
            modulus[i] = replacement[i];
    }

    // Forces EVERY mscorlib RSA verification to succeed, not just image signatures. BestHTTP's TLS
    // uses its own bundled BouncyCastle rather than mscorlib RSA, so this should not touch
    // certificate validation — but it is a blunt instrument, so it stays behind a config knob rather
    // than being unconditional.
    private static bool ForceVerifyTrue(ref bool __result)
    {
        if (!Plugin.DisableSignatureVerification.Value)
            return true;

        if (!_loggedForced)
        {
            _loggedForced = true;
            Plugin.Log.LogWarning("[SIG] signature verification disabled — RSA verify forced to true");
        }

        __result = true;
        return false;
    }

    [HarmonyPrefix]
    [HarmonyPatch(typeof(RSACryptoServiceProvider), nameof(RSACryptoServiceProvider.VerifyData))]
    private static bool VerifyDataPrefix(ref bool __result) => ForceVerifyTrue(ref __result);

    [HarmonyPrefix]
    [HarmonyPatch(typeof(RSACryptoServiceProvider), nameof(RSACryptoServiceProvider.VerifyHash),
        [typeof(Il2CppStructArray<byte>), typeof(int), typeof(Il2CppStructArray<byte>)])]
    private static bool VerifyHashPrefix(ref bool __result) => ForceVerifyTrue(ref __result);

    [HarmonyPrefix]
    [HarmonyPatch(typeof(RSACryptoServiceProvider), nameof(RSACryptoServiceProvider.VerifyHash),
        [typeof(Il2CppStructArray<byte>), typeof(Il2CppStructArray<byte>), typeof(HashAlgorithmName),
         typeof(RSASignaturePadding)])]
    private static bool VerifyHashPaddingPrefix(ref bool __result) => ForceVerifyTrue(ref __result);
}
