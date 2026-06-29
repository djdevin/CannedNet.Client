using System;
using BestHTTP;
using HarmonyLib;
using Il2CppInterop.Runtime;

namespace CannedNet.Client.Patches;

/**
    Intercept a variety of HTTP requests and rewrite them to point to our own custom server.
 */
public class SendRequestPatch
{
    // Official name server host to redirect away from, swapped for the custom server.
    private const string OfficialNameServer = "ns.rec.net";

    // Amplitude telemetry host; blocked outright (see Prefix).
    private const string AmplitudeHost = "api2.amplitude.com";

    // Skip when HTTP-logging so we don't spam the logs.
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
        // Returns false to skip the original SendRequest (drop the request entirely).
        private static bool Prefix(ref HTTPRequest request, ref HTTPRequest __result)
        {
            var debug = Plugin.Debug.Value && !IsIgnoredForLogging(request.Uri.AbsoluteUri);

            if (debug)
            {
                var entityBody = request.GetEntityBody();
                string body;
                if (entityBody == null)
                    body = "<none>";
                else if (IsBinaryContentType(request.GetFirstHeaderValue("content-type")) || LooksBinary(entityBody))
                    body = "<binary>";
                else
                    body = System.Text.Encoding.UTF8.GetString(entityBody);
                Plugin.Log.LogInfo($"[HTTP] {request.MethodType} {request.Uri.AbsoluteUri} body={body}");
            }

            var host = request.Uri.Host;
            if (host == AmplitudeHost)
            {
                // Amplitude telemetry hits real Amplitude (400 invalid_api_key) and Unity errors
                // on it. It's fire-and-forget, so drop it entirely: skip the original SendRequest
                // and hand the (undispatched) request back so callers don't NRE on a null return.
                if (debug)
                    Plugin.Log.LogInfo($"[HTTP] blocked {request.Uri.AbsoluteUri}");
                __result = request;
                return false;
            }

            if (host == OfficialNameServer)
            {
                // Redirect the nameserver lookup to the custom server.
                RewriteTo(request, Plugin.ServerHostname.Value, debug);
            }

            if (debug)
                LogResponseWhenDone(request);

            return true;
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
                        string text;
                        if (IsBinaryContentType(resp.GetFirstHeaderValue("content-type")))
                            text = "<binary>";
                        else
                        {
                            text = resp.DataAsText;
                            if (string.IsNullOrEmpty(text)) text = "<empty>";
                        }
                        var msg = $"[HTTP] <- {resp.StatusCode} {url} body={text}";
                        if (resp.StatusCode is >= 200 and < 300)
                            Plugin.Log.LogInfo(msg);
                        else
                            Plugin.Log.LogError(msg);
                    }

                    original?.Invoke(req, resp);
                }));
        }
        catch (Exception e)
        {
            Plugin.Log.LogError($"[HTTP] failed to attach response logger: {e}");
        }
    }

    // Content-Type prefixes/keywords we treat as textual; anything else is logged as <binary> so we
    // don't dump image/asset bytes into the log.
    private static readonly string[] TextContentTypes =
    {
        "text/", "application/json", "application/xml", "application/javascript",
        "application/x-www-form-urlencoded", "+json", "+xml",
    };

    // True if the body is (probably) binary and shouldn't be logged as text. Defaults to text when
    // there's no Content-Type, so we err toward logging rather than hiding.
    private static bool IsBinaryContentType(string contentType)
    {
        if (string.IsNullOrEmpty(contentType)) return false;

        foreach (var t in TextContentTypes)
            if (contentType.Contains(t, StringComparison.OrdinalIgnoreCase))
                return false;
        return true;
    }

    // Content sniff for raw request bytes — the Content-Type header isn't reliably set at
    // SendRequest time (e.g. multipart form bodies set it lazily, and the body still embeds the
    // raw image), so look at the bytes: a NUL byte, or a high ratio of non-text control bytes in
    // the first chunk, means it's binary (or binary-mixed like a multipart upload).
    private static bool LooksBinary(byte[] data)
    {
        if (data.Length == 0) return false;

        var sample = Math.Min(data.Length, 4096);
        var nonText = 0;
        for (var i = 0; i < sample; i++)
        {
            var b = data[i];
            if (b == 0) return true;
            // Control chars other than tab/newline/carriage-return.
            if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) nonText++;
        }
        return nonText * 100 / sample > 10;
    }

    // Rewrites the request to point at targetUrl (a full URL), keeping the original path + query.
    private static void RewriteTo(HTTPRequest request, string targetUrl, bool debug)
    {
        var target = new System.Uri(targetUrl);
        var uri = request.Uri;
        var port = target.IsDefaultPort ? "" : $":{target.Port}";
        var newUrl = $"{target.Scheme}://{target.Host}{port}{uri.PathAndQuery}";

        if (debug)
            Plugin.Log.LogInfo($"[HTTP] intercepted {uri.Host} -> {target.Host}");

        request.Uri = new Il2CppSystem.Uri(newUrl);
    }
}
