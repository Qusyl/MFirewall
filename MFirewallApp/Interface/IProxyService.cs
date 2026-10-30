using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Interface
{
    public interface IProxyService
    {
        Task<Result<string>> ValidateAsync(CancellationToken token);

    }
}