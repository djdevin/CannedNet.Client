using System;
using BestHTTP;
using HarmonyLib;
using Il2CppInterop.Runtime;

namespace CannedNet.Client.Patches;

public class SendRequestPatch
{
    // Official root domain to redirect away from. Any host under it (ns.rec.net,
    // api.rec.net, cdn.rec.net, ...) gets its root swapped for the custom server's root.
    private const string OfficialRoot = "rec.net";

    // Amplitude telemetry host; redirected to the custom datacollection service (see Prefix).
    private const string AmplitudeHost = "api2.amplitude.com";

    // Noisy/uninteresting endpoints to skip when HTTP-logging (telemetry spam). The host rewrite
    // still applies to these — only the logging is suppressed.
    private static readonly string[] LogIgnoreSubstrings =
    {
        "datacollection",
        "/api/gamesight/event",
        "api2.amplitude.com",
    };

    private static bool IsIgnoredForLogging(string url)
    {
        foreach (var s in LogIgnoreSubstrings)
            if (url.Contains(s, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    [HarmonyPatch(typeof(HTTPManager), "SendRequest", [typeof(HTTPRequest)])]
    public class ConnectToRecNetPatch
    {
        private static void Prefix(ref HTTPRequest request)
        {
            var debug = Plugin.Debug.Value && !IsIgnoredForLogging(request.Uri.AbsoluteUri);

            if (debug)
            {
                var entityBody = request.GetEntityBody();
                var body = entityBody != null
                    ? System.Text.Encoding.UTF8.GetString(entityBody)
                    : "<none>";
                var auth = request.HasHeader("Authorization")
                    ? request.GetFirstHeaderValue("Authorization")
                    : "<none>";
                Plugin.Log.LogInfo($"[HTTP] {request.MethodType} {request.Uri.AbsoluteUri} auth={auth} body={body}");
            }

            var host = request.Uri.Host;
            string newHost = null;
            if (host == OfficialRoot || host.EndsWith("." + OfficialRoot))
            {
                // Preserve the subdomain, swap only the root: api.rec.net -> api.my.new-rec.net
                newHost = host.Substring(0, host.Length - OfficialRoot.Length) + GetBaseDomain();
            }
            else if (host == AmplitudeHost)
            {
                // Amplitude telemetry hits real Amplitude (400 invalid_api_key) and Unity errors
                // on it; redirect to our datacollection service so the backend can swallow it.
                newHost = "datacollection." + GetBaseDomain();
            }

            if (newHost != null)
            {
                var uri = request.Uri;
                var port = uri.IsDefaultPort ? "" : $":{uri.Port}";
                var newUrl = $"{uri.Scheme}://{newHost}{port}{uri.PathAndQuery}";

                if (debug)
                {
                    Plugin.Log.LogInfo($"[HTTP] intercepted {host} -> {newHost}");
                }
                request.Uri = new Il2CppSystem.Uri(newUrl);
            }

            if (debug)
            {
                LogResponseWhenDone(request);
                CaptureSentHeaders(request);
            }
        }
    }

    // RecNet writes some headers (notably Authorization) straight to the socket via BestHTTP's
    // OnSendingHeaders callback, bypassing the header dictionary — so EnumerateHeaders never sees
    // them. Tee that callback: run the original into a MemoryStream, log the bytes, then replay
    // them to the real stream so the request goes out unchanged.
    private static void CaptureSentHeaders(HTTPRequest request)
    {
        try
        {
            var orig = request.OnSendingHeaders;
            if (orig == null) return;
            var url = request.Uri.AbsoluteUri;

            request.OnSendingHeaders = DelegateSupport.ConvertDelegate<Il2CppSystem.Action<HTTPRequest, Il2CppSystem.IO.Stream>>(
                (Action<HTTPRequest, Il2CppSystem.IO.Stream>)((req, realStream) =>
                {
                    var forwarded = false;
                    try
                    {
                        var mem = new Il2CppSystem.IO.MemoryStream();
                        orig.Invoke(req, mem);
                        var bytes = mem.ToArray();
                        Plugin.Log.LogInfo($"[HTTP] -> wire headers for {url}: {System.Text.Encoding.UTF8.GetString(bytes)}");
                        if (bytes.Length > 0) realStream.Write(bytes, 0, bytes.Length);
                        forwarded = true;
                    }
                    catch (Exception e)
                    {
                        Plugin.Log.LogError($"[HTTP] failed to capture wire headers: {e}");
                    }

                    // If capture failed before writing, fall back so the headers still go out.
                    if (!forwarded)
                        orig.Invoke(req, realStream);
                }));
        }
        catch (Exception e)
        {
            Plugin.Log.LogError($"[HTTP] failed to attach wire-header logger: {e}");
        }
    }

    // Wraps the request's completion callback so we log the response (status + body) when it
    // finishes, then forwards to the game's original callback. This is how we see *which*
    // request comes back empty (RecNet throws "Response was empty" on a blank body).
    private static void LogResponseWhenDone(HTTPRequest request)
    {
        try
        {
            var original = request.Callback;
            var url = request.Uri.AbsoluteUri;

            request.Callback = DelegateSupport.ConvertDelegate<OnRequestFinishedDelegate>(
                (Action<HTTPRequest, HTTPResponse>)((req, resp) =>
                {
                    if (resp == null)
                        Plugin.Log.LogWarning($"[HTTP] <- {url} NO RESPONSE (state={req.State})");
                    else
                    {
                        var text = resp.DataAsText;
                        if (string.IsNullOrEmpty(text)) text = "<empty>";
                        else if (text.Length > 1000) text = text.Substring(0, 1000) + "...<truncated>";
                        Plugin.Log.LogInfo($"[HTTP] <- {resp.StatusCode} {url} body={text}");
                    }

                    original?.Invoke(req, resp);
                }));
        }
        catch (Exception e)
        {
            Plugin.Log.LogError($"[HTTP] failed to attach response logger: {e}");
        }
    }

    // Base domain of the custom server: the configured host with the leading "ns." stripped.
    // "https://ns.my.new-rec.net" -> "my.new-rec.net" so we can prefix the other API endpoints.
    private static string GetBaseDomain()
    {
        var host = new System.Uri(Plugin.ServerHostname.Value).Host;
        return host.StartsWith("ns.") ? host.Substring(3) : host;
    }
}