using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using MFirewallApp.Validators;

namespace MFirewallApi.Middlewares
{
    public class JwtTokenMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtTokenMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, JwtValidator validator)
        {
            var header = context.Request.Headers.Authorization.ToString();
            if (header.StartsWith("Bearer ") && validator.TryValidate(header["Bearer ".Length..], out var payload))
            {
                var claims = payload.EnumerateObject().SelectMany(
                    p => p.Value.ValueKind == System.Text.Json.JsonValueKind.Array
                    ? p.Value.EnumerateArray().Select(v => new Claim(p.Name, v.GetString()!))
                    : new[] { new Claim(p.Name, p.Value.ToString()) });

                context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "CustomJwt"));
            }
            await _next(context);
        } 
    }
}