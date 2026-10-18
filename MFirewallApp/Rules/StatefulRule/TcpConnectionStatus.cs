using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.StatefulRule
{
    public enum TcpConnectionStatus
    {
        SynSent,
        SynReceived,

        Established,

        Closing,
        Closed
    }
}