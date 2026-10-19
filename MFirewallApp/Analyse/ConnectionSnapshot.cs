using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Rules.StatefulRule;

namespace MFirewallApp.Analyse
{
    public sealed record ConnectionSnapshot(ConnectionKey ConnectionKey, ConnectionState ConnectionState);
}