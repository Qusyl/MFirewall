using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using MFirewallApp.Interface;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;

namespace MFirewallApp.Service
{
    public class HttpForwarder(IHttpClientFactory httpClientFactory,ILogger<IHttpForwarder> logger) : IHttpForwarder
    {
        private readonly IHttpClientFactory _httpClient = httpClientFactory;

        private readonly ILogger<IHttpForwarder> _logger = logger;

        public async Task ForwardAsync(HttpContext context, CancellationToken cts)
        {
            Console.WriteLine("HTTP FORWARDER INVOKED!");
            var request = context.Request;

            var targetUri = new Uri(UriHelper.GetEncodedUrl(request));

            var forribdenHeaders = new List<string>
            {
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "proxy-connection",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade"
            };
            _logger.LogInformation("Target uri: {0}", targetUri.ToString());
            
            
           using var proxyRequest = new HttpRequestMessage(new HttpMethod(request.Method), targetUri);

            if (
            HttpMethods.IsPost(request.Method) ||
            HttpMethods.IsPut(request.Method) ||
            HttpMethods.IsPatch(request.Method))
            {
                proxyRequest.Content = new StreamContent(request.Body);
            }
            foreach (var header in request.Headers)
            {
                if(header.Key.ToLower() == "authorization")
                {
                    continue;
                }
                if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) || forribdenHeaders.Contains(header.Key.ToLower()))
                {
                    continue;
                }
                
                if (!proxyRequest.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()) && proxyRequest.Content != null)
                {
                    proxyRequest.Content.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }

            proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-Host", request.Host.Value);

            var clientIp = context.Connection.RemoteIpAddress?.ToString();

            if (!string.IsNullOrWhiteSpace(clientIp))
            {
                proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-For", clientIp);
            }

            proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-Proto", request.Scheme);

            using var client = _httpClient.CreateClient("ForwardProxy");

            using var serverResponse = await client.SendAsync(proxyRequest, HttpCompletionOption.ResponseHeadersRead, cts);

            
            _logger.LogInformation("ServerResponse[{0}]", serverResponse.StatusCode.ToString());

            context.Response.StatusCode = (int)serverResponse.StatusCode;

            foreach (var header in serverResponse.Headers)
            {
                if (!forribdenHeaders.Contains(header.Key.ToLower()))
                {
                     context.Response.Headers[header.Key] = header.Value.ToArray();
                }
               
            }

            foreach (var header in serverResponse.Content.Headers)
            {
                if (!forribdenHeaders.Contains(header.Key.ToLower()))
                {
                    context.Response.Headers[header.Key] = header.Value.ToArray();
                }

            }

       
             _logger.LogInformation("ServerResponse[{0}]", serverResponse.Content.ToString());
            await serverResponse.Content.CopyToAsync(context.Response.Body, cts);

        }
    }
}