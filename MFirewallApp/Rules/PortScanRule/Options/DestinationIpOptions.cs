using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.PortScanRule.Options
{
    public sealed class DestinationIpOptions
    {
        public bool Enable { get; set; } = true;

        public string DestinationAddress { get; set; } = string.Empty;
    }
}