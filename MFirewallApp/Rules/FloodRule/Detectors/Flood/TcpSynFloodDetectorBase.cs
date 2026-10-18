using System;
using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.FloodRule.Detectors.Flood
{
    public abstract class TcpSynFloodDetectorBase
    {
        protected readonly ConcurrentDictionary<PacketSource, PacketHistory> _history;

        public TcpSynFloodDetectorBase(ConcurrentDictionary<PacketSource, PacketHistory> history)
        {
            _history = history;
        }

        public abstract PacketDecision ShouldBlock(IPv4Packet packet, FirewallProtection configuration);
        protected void ClearExpiredPackets(DateTimeOffset now, TimeSpan window)
        {
            if (_history.IsEmpty)
            {
                return;
            }
            DateTimeOffset cutoff = now - window;

            foreach(var (packet, history) in _history)
            {
                history.TrimOlderThan(cutoff);

                if (history.IsEmpty)
                {
                    _history.TryRemove(packet, out _);
                }
            }
        }
    }
}