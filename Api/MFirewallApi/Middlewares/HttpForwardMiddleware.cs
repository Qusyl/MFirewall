using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Interface;

namespace MFirewallApi.Middlewares
{
    public class HttpForwardMiddleware
    {
        private readonly RequestDelegate _next;

        public HttpForwardMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IHttpForwarder forwarder)
        {
            if (!ProxyRequestDetector.IsProxyRequest(context))
            {
                await _next(context);
                return;
            }
            await forwarder.ForwardAsync(context, context.RequestAborted);

        }   
    }
}