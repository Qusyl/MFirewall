using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.RateLimitRule
{
    public enum RateLimitScope
    {
        PORT,
        IP,
        PROTOCOL
    }
}