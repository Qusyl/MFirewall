using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Rules;

namespace MFirewallApp.Interface
{
    public interface IPacketRule
    {
        public int RuleScore { get; }
        string RuleName { get; }
        Verdict.Verdict Check(IPv4Packet packet, RuleParameters configuration);
    }
}