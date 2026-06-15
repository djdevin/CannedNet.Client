using HarmonyLib;

namespace CannedNet.Client.Patches;

// GOBAHJBPPEM is a static game-config / feature-flag helper. The bool property HJLNMINPFNG (its
// il2cpp getter is LBPOALIGKJL) reads a config-backed Nullable<bool> via .Value. On the private
// backend that config key is never supplied (it's not in /api/gameconfigs/v1/all), so the Nullable
// has no value and every read throws InvalidOperationException ("Nullable object must have a value").
// This flag is polled in ~12 places (it surfaced via LeaderboardView's scheduled update, which then
// requeues forever on the exception).
//
// Since the original always throws here, returning a safe default (false = feature off) and skipping
// the original is strictly better. If the flag should actually be on, the correct fix is to add its
// key to the backend's gameconfigs instead.
//
// Obfuscated names change per game build; re-find HJLNMINPFNG (the throwing static bool getter on
// GOBAHJBPPEM) with ilspycmd if the build updates.
//
// @TODO: not sure if this is a blocker to joining a room
[HarmonyPatch(typeof(global::GOBAHJBPPEM), "HJLNMINPFNG", MethodType.Getter)]
public class GameConfigFlagPatch
{
    private static bool Prefix(ref bool __result)
    {
        __result = false;
        return false; // skip the original, which throws on the unset Nullable
    }
}
