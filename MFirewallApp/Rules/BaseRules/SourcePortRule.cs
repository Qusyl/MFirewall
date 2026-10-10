using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Domain.Models.Packets;
using MFirewallApp.Interface;

namespace MFirewallApp.Rules.BaseRules
{
    public class SourcePortRule : IPacketRule
    {
        public string RuleName => "source_port_rule";

        public int RuleScore => 15;

        public Verdict.Verdict Check(IPv4Packet packet, RuleParameters configuration)
        {
                var transportPacket = packet.ExtractPacket();
                int port = transportPacket switch
                {
                    UdpPacket udp => udp.Header.SourcePort,
                    TcpPacket tcp => tcp.Header.SourcePort,
                    IcmpPacket icmpPacket => -1,
                    _ => throw new SwitchExpressionException($"Not found packet type : {transportPacket.PacketType}")
                };

                if (port != -1)
                {
                    if (port == configuration.SourcePortRule)
                    {
                        return Verdict.Verdict.DROP;
                    }
                    return Verdict.Verdict.ACCEPT;
                }
            
            return Verdict.Verdict.NO_MATCH;
        }
    }
}