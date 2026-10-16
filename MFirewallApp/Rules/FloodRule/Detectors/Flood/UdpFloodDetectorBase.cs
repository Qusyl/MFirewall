
using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;

namespace MFirewallApp.Rules.FloodRule.Detectors.Flood
{
    public abstract class UdpFloodDetectorBase
    {
        protected ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, PacketHistory>> _history;

        public UdpFloodDetectorBase(ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, PacketHistory>> history)
        {
            _history = history;
        }
        public abstract Verdict.Verdict ShouldBlock(IPv4Packet packet, FirewallProtection configuration);

        protected void ClearExpiredPackets(DateTimeOffset now, TimeSpan window)
        {
            if (_history.IsEmpty)
            {
                return;
            }
            DateTimeOffset cutoff = now - window;

            foreach(var (packet, portHistories) in _history)
            {
               foreach(var (_, history) in portHistories)
                {
                    history.TrimOlderThan(cutoff);

                    if(history.IsEmpty)
                    {
                        _history.TryRemove(packet, out _);
                    }
                }
            }
        }
    } 
}