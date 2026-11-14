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