using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.FloodRule.Detectors.Flood
{
    public sealed class TcpSynFloodDetector : TcpSynFloodDetectorBase
    {
        public TcpSynFloodDetector(ConcurrentDictionary<PacketSource, PacketHistory> history) : base(history)
        {
        }

        public override PacketDecision ShouldBlock(IPv4Packet packet, FirewallProtection configuration)
        {
            if (!configuration.TcpSynFloodOptions.Enable)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", "tcp syn flood detector");
            }

            if (packet.ExtractPacket() is TcpPacket tcp)
            {
                if (tcp.Header.IsAck || !tcp.Header.IsSyn)
                {
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not syn", "tcp syn flood detector");
                }
        
                var maxPackets = configuration.TcpSynFloodOptions.MaxSynPackets;
                var window = TimeSpan.FromSeconds(configuration.TcpSynFloodOptions.WindowSeconds);
                var now = DateTimeOffset.UtcNow;

                var packetSource = new PacketSource(packet.Header.SourceAddress, packet.Header.DestinationAddress, Protocol.TCP);

                ClearExpiredPackets(now, window);

                if (_history.TryGetValue(packetSource, out var history))
                {
                    if (!history.TryRegister(now, window, maxPackets))
                    {
                        return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"tcp packets exceeded [{maxPackets}]", "udp flood detector");
                    }
                }

                var newHistory = new PacketHistory();

                newHistory.TryRegister(now, window, maxPackets);

                _history.TryAdd(packetSource, newHistory);

                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "No reason for drop", "tcp syn flood detector");
            }

            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Packet is not tcp", "udp flood detector");
        }
    }
}