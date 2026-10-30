using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.HttpProxyOptions
{
    public class AllowedDomainOptions
    {
        public List<string> AllowedDomains { get; set; } = new() { "*" };
    }
}