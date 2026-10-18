
using System.Runtime.CompilerServices;
using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.BaseRules
{
    public class SourcePortRule : IPacketRule
    {
        public string RuleName => "source_port_rule";

        public int RuleScore => 15;

        public PacketDecision Check(IPv4Packet packet, FirewallProtection configuration)
        {
            if (!configuration.SourcePortOptions.Enable)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", RuleName);
            }
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
                var configPort = configuration.SourcePortOptions.SourcePort;
                if (port == configPort )
                {
                    FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.DROP.ToString()}");
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"SOURCE PORT matched [{port}][{configPort}]", RuleName);
                }
                    FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.ACCEPT.ToString()}");
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, $"SOURCE PORT not matched [{port}][{configPort}]", RuleName);
                }
            
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Packet type not supported for current rule", RuleName);
        }
    }
}