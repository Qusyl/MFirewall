

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

            var transportPacket = packet.ExtractPacket();

            if (transportPacket is TcpPacket)
            {
                var UdpDetector = new UdpFloodDetector(udpHistory);

                var verdict = UdpDetector.ShouldBlock(packet, configuration);

                return verdict;
            }
            else
            {
                var TcpDetector = new TcpSynFloodDetector(tcpHistory);

                var verdict = TcpDetector.ShouldBlock(packet, configuration);

                return verdict;
            }
        }
    }
}