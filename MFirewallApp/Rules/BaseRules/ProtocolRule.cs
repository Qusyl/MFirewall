using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.BaseRules
{
    public class ProtocolRule : IPacketRule
    {
        public string RuleName => "protocol_rule";

        public int RuleScore => 10;

        public PacketDecision Check(IPv4Packet packet, FirewallProtection configuration)
        {
            if (!configuration.ProtocolOptions.Enable)
            {
              
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", RuleName);
            }

            var configProtocol = configuration.ProtocolOptions.Protocol;

            var packetProtocol = packet.Header.Protocol;

            FileLogger.AppendLogFile($"[PROTOCOL_RULE] {packetProtocol} = {configProtocol}?");
            if ( configProtocol==packetProtocol )
            {
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.DROP.ToString()}");
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"Protocol matched [{configProtocol}][{packetProtocol}]", RuleName);
            }
            FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.ACCEPT.ToString()}");
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, $"Protocol not matched [{configProtocol}][{packetProtocol}]", RuleName);
        }
    }
}