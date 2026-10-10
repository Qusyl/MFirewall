using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Values;

namespace MFirewallApp.Rules
{
    public class RuleParameters
    {
    public string DestinationIpRule { get; set; } = string.Empty;
    public int DestinationPortRule { get; set; }
    public ProtocolFromBytes ProtocolRule { get; set; } = ProtocolFromBytes.None;
    public string SourceIpRule { get; set; } = string.Empty;
    public int SourcePortRule { get; set; }
    public int UniquePortsThreshold { get; set; }
    public int SynWindow { get; set; }
    }
}