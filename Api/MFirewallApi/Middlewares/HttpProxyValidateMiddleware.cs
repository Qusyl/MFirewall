using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Interface;
using MFirewallApp.Rules;
using Microsoft.Extensions.Options;

namespace MFirewallApi.Middlewares
{
    public class HttpProxyValidateMiddleware
    {
        private readonly RequestDelegate _next;

        public HttpProxyValidateMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IProxyService proxyService, IOptionsMonitor<HttpProxyConfiguration> config)
        {
            if (HttpMethods.IsConnect(context.Request.Method))
            {
                if (!ProxyRequestDetector.TryGetConnectTarget(context, out var host, out var port))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;

                    return;
                }

                System.Console.WriteLine($"CONNECTION HOST:{host}");
                System.Console.WriteLine($"CONNECTION PORT:{port}");
                var allowedPorts = config.CurrentValue.HttpsOptions.AllowedPorts;
                if (!allowedPorts.Contains(port))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync($"Port {port} is found on blocked ports");
                    return;
                }

                context.Response.StatusCode = StatusCodes.Status501NotImplemented;

                return;
            }
            if (!ProxyRequestDetector.IsProxyRequest(context))
            {
                await _next(context);
                return;
            }

            var result = await proxyService.ValidateAsync(context.RequestAborted);

            if (!result.IsSuccess)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync(
                result.Error ?? "Forbidden"
                );
                return;
            }
            await _next(context);
            
        }
    }
}