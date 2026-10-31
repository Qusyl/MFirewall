using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Features;

namespace MFirewallApi.Middlewares
{
    public static class ProxyRequestDetector
    {
        public static bool TryGetConnectTarget(HttpContext context, out string host, out int port)
        {
            host = string.Empty;

            port = 0;

            if (!HttpMethods.IsConnect(context.Request.Method))
            {
                return false;
            }

            var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;

            if (string.IsNullOrWhiteSpace(rawTarget))
            {
                return false;
            }

            if (!Uri.TryCreate("https://" + rawTarget, UriKind.Absolute, out var httpsUri))
            {
                return false;
            }

            bool hasPort;

            if (rawTarget.StartsWith("["))
            {
                var closingBracket = rawTarget.IndexOf("]");

                hasPort = closingBracket > 0
               && closingBracket + 1 < rawTarget.Length
               && rawTarget[closingBracket + 1] == ':';
            }
            else
            {
                hasPort = rawTarget.Count(c => c == ':') == 1;
            }

            if (!hasPort
            || !string.IsNullOrWhiteSpace(httpsUri.UserInfo)
            || httpsUri.AbsolutePath != "/"
            || !string.IsNullOrWhiteSpace(httpsUri.Query)
            || !string.IsNullOrWhiteSpace(httpsUri.Fragment)
            || httpsUri.Port < 1
            || httpsUri.Port > 65535
            )
            {
                return false;
            }

            host = httpsUri.Host;
            port = httpsUri.Port;

            return !string.IsNullOrWhiteSpace(host);
        }
        public static bool IsProxyRequest(HttpContext context)
        {
            var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;

            return Uri.TryCreate(rawTarget, UriKind.Absolute, out var uri) 
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
        }
    }
}