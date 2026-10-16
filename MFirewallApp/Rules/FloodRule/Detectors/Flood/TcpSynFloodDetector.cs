using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models.Packets;
using Domain.Values;

namespace MFirewallApp.Rules.FloodRule.Detectors.Flood
{
    public sealed class TcpSynFloodDetector : TcpSynFloodDetectorBase
    {
        public TcpSynFloodDetector(ConcurrentDictionary<PacketSource, PacketHistory> history) : base(history)
        {
        }

        public override Verdict.Verdict ShouldBlock(IPv4Packet packet, FirewallProtection configuration)
        {
            if (!configuration.TcpSynFloodOptions.Enable)
            {
                return Verdict.Verdict.NO_MATCH;
            }

            if (packet.ExtractPacket() is TcpPacket tcp)
            {
                if (tcp.Header.IsAck || !tcp.Header.IsSyn)
                {
                    return Verdict.Verdict.NO_MATCH;
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
                        return Verdict.Verdict.DROP;
                    }
                }

                var newHistory = new PacketHistory();

                newHistory.TryRegister(now, window, maxPackets);

                _history.TryAdd(packetSource, newHistory);

                return Verdict.Verdict.ACCEPT;
            }

            return Verdict.Verdict.NO_MATCH;
        }
    }
}