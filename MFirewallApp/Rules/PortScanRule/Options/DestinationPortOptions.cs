using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.PortScanRule.Options
{
    public sealed class DestinationPortOptions
    {
        public bool Enable { get; set; } = true;

        public int DestinationPort { get; set; } = 0;
    }
}