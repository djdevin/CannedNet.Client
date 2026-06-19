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
    // Official root domain to redirect away from. Any host under it (ns.rec.net,
    // api.rec.net, cdn.rec.net, ...) gets its root swapped for the custom server's root.
    private const string OfficialRoot = "rec.net";

    // Amplitude telemetry host; redirected to the custom datacollection service.
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
        private static void Prefix(ref HTTPRequest request)
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
                {
                    body = System.Text.Encoding.UTF8.GetString(entityBody);
                    if (body.Length > 1000) body = body.Substring(0, 1000) + "...<truncated>";
                }
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
                        // Uncomment if you need to see the raw headers in the logs.
                        //Plugin.Log.LogInfo($"[HTTP] -> wire headers for {url}: {System.Text.Encoding.UTF8.GetString(bytes)}");
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
                        string text;
                        if (IsBinaryContentType(resp.GetFirstHeaderValue("content-type")))
                            text = "<binary>";
                        else
                        {
                            text = resp.DataAsText;
                            if (string.IsNullOrEmpty(text)) text = "<empty>";
                            else if (text.Length > 1000) text = text.Substring(0, 1000) + "...<truncated>";
                        }
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

    // Base domain of the custom server: the configured host with the leading "ns." stripped.
    // "https://ns.my.new-rec.net" -> "my.new-rec.net" so we can prefix the other API endpoints.
    private static string GetBaseDomain()
    {
        var host = new System.Uri(Plugin.ServerHostname.Value).Host;
        return host.StartsWith("ns.") ? host.Substring(3) : host;
    }
}
