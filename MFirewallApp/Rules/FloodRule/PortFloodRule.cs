

using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Interface;
using MFirewallApp.Rules.FloodRule.Detectors.Flood;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.FloodRule
{
    public class SyncFloodRule : IPacketRule
    {
        public string RuleName => "port_flood_rule";

        public int RuleScore => 100;

        private readonly ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, PacketHistory>> udpHistory = new();

        private readonly ConcurrentDictionary<PacketSource, PacketHistory> tcpHistory = new();

        public PacketDecision Check(IPv4Packet packet, FirewallProtection configuration)
        {
            if(!configuration.TcpSynFloodOptions.Enable && !configuration.UdpFloodOptions.Enable)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", RuleName);
            }

            var transportPacket = packet.ExtractPacket();

            if (transportPacket is TcpPacket && configuration.TcpSynFloodOptions.Enable)
            {
                var tcpDetector = new TcpSynFloodDetector(tcpHistory);

                var verdict = tcpDetector.ShouldBlock(packet, configuration);

                return verdict;
            }
            if(transportPacket is UdpPacket && configuration.UdpFloodOptions.Enable)
            {
                var udpDetector = new UdpFloodDetector(udpHistory);

                var verdict = udpDetector.ShouldBlock(packet, configuration);

                return verdict;
            }
            else
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", RuleName);
            }
        }
    }
}