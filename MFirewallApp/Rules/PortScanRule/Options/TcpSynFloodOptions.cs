using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.PortScanRule
{
    public sealed class TcpSynFloodOptions
    {
        public bool Enable { get; set; } = true;
        public int MaxSynPackets { get; set; } = 100;

        public int WindowSeconds { get; set; } = 3;

    }
}