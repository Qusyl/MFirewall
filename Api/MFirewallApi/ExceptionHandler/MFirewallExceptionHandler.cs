using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace MFirewallApi.ExceptionHandler
{
    public class MFirewallExceptionHandler : IExceptionHandler
    {
        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            var details = new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Inner application error",
                Detail = exception.Message,
                Instance = httpContext.Request.Path
            };
            httpContext.Response.StatusCode = details.Status.Value;

            await httpContext.Response.WriteAsJsonAsync(details, cancellationToken);

            return true;
            
        }
    }
}