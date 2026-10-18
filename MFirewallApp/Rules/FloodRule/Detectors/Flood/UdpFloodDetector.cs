using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.FloodRule.Detectors.Flood
{
    public sealed class UdpFloodDetector : UdpFloodDetectorBase
    {
        public UdpFloodDetector(ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort,PacketHistory>> history) : base(history)
        {
            
        }

        public override PacketDecision ShouldBlock(IPv4Packet packet, FirewallProtection configuration)
        {
            if (!configuration.UdpFloodOptions.Enable)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", "udp flood detector");
            }

            if (packet.ExtractPacket() is UdpPacket udp)
            {
                var maxPackets = configuration.UdpFloodOptions.MaxPackets;

                var window = TimeSpan.FromSeconds(configuration.UdpFloodOptions.WindowSeconds);

                var now = DateTimeOffset.UtcNow;

                var port = udp.Header.DestinationPort;

                var packetSource = new PacketSource(packet.Header.SourceAddress, packet.Header.DestinationAddress, Protocol.UDP);

                ClearExpiredPackets(now, window);

                if (_history.TryGetValue(packetSource, out var portHistory))
                {
                    if (portHistory.TryGetValue(port, out var history))
                    {
                        if (!history.TryRegister(now, window, maxPackets))
                        {
                            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"udp port packets exceeded", "udp flood detector");
                        }
                    }
                }
                
                var newHistory = new PacketHistory();

                    newHistory.TryRegister(now, window, maxPackets);

                    var portHistoryDictionary = new ConcurrentDictionary<ushort, PacketHistory>();

                    portHistoryDictionary.TryAdd(port, newHistory);

                    _history.TryAdd(packetSource, portHistoryDictionary);

                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "No reason for drop", "udp flood detector");
            }
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, $"packet is not udp", "udp flood detector");
        }
    }
}