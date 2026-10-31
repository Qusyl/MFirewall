using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.HttpProxyOptions
{
    public class HttpsOptions
    {
        public List<int> AllowedPorts { get; set; } = new();
    }
}