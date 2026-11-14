using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.PortScanRule.Options
{
    public sealed class DestinationIpOptions
    {
        public bool Enable { get; set; } = true;

        public ObservableCollection<string> DestinationAddress { get; set; } = new();
    }
}