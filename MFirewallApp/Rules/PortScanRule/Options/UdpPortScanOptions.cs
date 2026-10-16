using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.PortScanRule.Options
{
    public class UdpPortScanOptions
    {
        public bool Enable { get; set; } = true;

        public int UniquePacketsThreshold { get; set; } = 10;

        public int WindowSeconds { get; set; } = 3;
    }
}