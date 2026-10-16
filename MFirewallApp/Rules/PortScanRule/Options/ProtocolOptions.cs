using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Values;

namespace MFirewallApp.Rules.PortScanRule.Options
{
    public sealed class ProtocolOptions
    {
        public bool Enable { get; set; } = true;

        public Protocol Protocol { get; set; } = Protocol.NONE;
    }
}