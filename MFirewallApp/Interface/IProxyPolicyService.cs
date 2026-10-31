using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace MFirewallApp.Interface
{
    public interface IProxyPolicyService
    {
        Task<Result<string>> ShouldAccept(HttpRequest request);

    
    }
}