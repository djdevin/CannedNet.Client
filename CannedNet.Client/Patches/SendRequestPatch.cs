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

    [HarmonyPatch(typeof(HTTPManager), "SendRequest", [typeof(HTTPRequest)])]
    public class ConnectToRecNetPatch
    {
        private static void Prefix(ref HTTPRequest request)
        {
            if (Plugin.Debug.Value)
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
            if (host == OfficialRoot || host.EndsWith("." + OfficialRoot))
            {
                // Preserve the subdomain, swap only the root: api.rec.net -> api.my.new-rec.net
                var newHost = host.Substring(0, host.Length - OfficialRoot.Length) + GetBaseDomain();

                var uri = request.Uri;
                var port = uri.IsDefaultPort ? "" : $":{uri.Port}";
                var newUrl = $"{uri.Scheme}://{newHost}{port}{uri.PathAndQuery}";

                if (Plugin.Debug.Value)
                {
                    Plugin.Log.LogInfo($"[HTTP] intercepted {host} -> {newHost}");
                }
                request.Uri = new Il2CppSystem.Uri(newUrl);
            }

            if (Plugin.Debug.Value)
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
                    // By now BestHTTP's before-send callback has run, so headers RecNet adds
                    // lazily (e.g. Authorization) are populated on the request — log them here.
                    Plugin.Log.LogInfo($"[HTTP] -> headers for {url}: {DumpHeaders(req)}");

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

    // Enumerates all headers currently on the request (BestHTTP's own enumeration, no
    // before-send re-invoke) into a single "Name: v1,v2; Name2: v3" string for logging.
    private static string DumpHeaders(HTTPRequest req)
    {
        var sb = new System.Text.StringBuilder();
        req.EnumerateHeaders(DelegateSupport.ConvertDelegate<OnHeaderEnumerationDelegate>(
            (Action<string, Il2CppSystem.Collections.Generic.List<string>>)((name, values) =>
            {
                sb.Append(name).Append(": ");
                for (int i = 0; i < values.Count; i++)
                    sb.Append(i > 0 ? "," : "").Append(values[i]);
                sb.Append("; ");
            })));
        return sb.Length == 0 ? "<none>" : sb.ToString();
    }

    // Base domain of the custom server: the configured host with the leading "ns." stripped.
    // "https://ns.my.new-rec.net" -> "my.new-rec.net" so we can prefix the other API endpoints.
    private static string GetBaseDomain()
    {
        var host = new System.Uri(Plugin.ServerHostname.Value).Host;
        return host.StartsWith("ns.") ? host.Substring(3) : host;
    }
}