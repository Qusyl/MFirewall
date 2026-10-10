using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.FileSystem;
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
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.NO_MATCH.ToString()}");
                return Verdict.Verdict.NO_MATCH;
            }
            if (configuration.ProtocolRule == packet.Header.Protocol)
            {
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.DROP.ToString()}");
                return Verdict.Verdict.DROP;
            }
            FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.ACCEPT.ToString()}");
            return Verdict.Verdict.ACCEPT;
        
         
        }
    }
}