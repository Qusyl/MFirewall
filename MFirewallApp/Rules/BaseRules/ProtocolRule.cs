using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Interface;

namespace MFirewallApp.Rules.BaseRules
{
    public class ProtocolRule : IPacketRule
    {
        public string RuleName => "protocol_rule";

        public int RuleScore => 10;

        public Verdict.Verdict Check(IPv4Packet packet, RuleParameters configuration)
        {
            if(configuration.ProtocolRule == ProtocolFromBytes.None)
            {
                return Verdict.Verdict.NO_MATCH;
            }
            if (configuration.ProtocolRule == packet.Header.Protocol)
            {
                return Verdict.Verdict.DROP;
            }
                
            return Verdict.Verdict.ACCEPT;
        
         
        }
    }
}