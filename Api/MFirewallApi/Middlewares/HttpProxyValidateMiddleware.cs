using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Interface;

namespace MFirewallApi.Middlewares
{
    public class HttpProxyValidateMiddleware
    {
        private readonly RequestDelegate _next;

        public HttpProxyValidateMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IProxyService proxyService)
        {
           var token = context.RequestAborted;  
           var result = await proxyService.ValidateAsync(token);

            if (!result.IsSuccess)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/plain; charset=utf-8";
                await context.Response.WriteAsync(result.Error ?? "Forbidden");
                return;
            }

            await _next(context);
        }
    }
}