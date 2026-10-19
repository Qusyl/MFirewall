using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Verdict;

namespace MFirewallApp.Analyse
{
    public sealed record FirewallReport(
        DateTimeOffset Identified,
        PacketDecision PacketDecision
    );
}