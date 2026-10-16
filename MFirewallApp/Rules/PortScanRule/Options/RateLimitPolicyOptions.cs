using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.PortScanRule.Options
{
    public sealed class RateLimitPolicyOptions
    {
        public bool Enable { get; set; } = true;

        public int MaxPackets { get; set; } = 100;

        public int WindowSeconds { get; set; } = 1;
    }
}