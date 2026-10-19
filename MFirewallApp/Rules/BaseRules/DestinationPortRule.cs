using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.BaseRules
{
    public class DestinationPortRule : IPacketRule
    {
        public string RuleName => "destination_port_rule";

        public int RuleScore => 40;

        public PacketDecision Check(IPv4Packet packet,FirewallProtection configuration)
        {
            if (!configuration.DestinationPortOptions.Enable)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", RuleName);
            }
            var transportPacket = packet.ExtractPacket();
                
                int port = transportPacket switch
                {
                    UdpPacket udp => udp.Header.DestinationPort,
                    TcpPacket tcp => tcp.Header.DestinationPort,
                    IcmpPacket icmpPacket => -1,
                    _ => throw new SwitchExpressionException($"Not found packet type : {transportPacket.PacketType}")
                };
           
                if (port != -1)
            {
                var configPort = configuration.DestinationPortOptions.DestinationPort;
                
                if (port == configPort)
                {
                   
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"Destination port matched [{port}] [{configPort}]", RuleName);
                }
                  
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, $"Destination port not matched [{port}] [{configPort}]", RuleName);
                }
            
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Packet type not supported for current rule", RuleName);
        }
    }
}