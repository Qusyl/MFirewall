using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;

namespace MFirewallApp.Rules.PortScanRule.Detectors.PortScan
{
    public abstract class PortScanDetector
    {
        protected readonly ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>> _attempts;

        public PortScanDetector(ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>> attempts)
        {
            _attempts = attempts;
        }
        public abstract Verdict.Verdict ShouldBlock(IPv4Packet packet, FirewallProtection configuration);
        protected void ClearExpiredPorts(DateTimeOffset thresholdTime)
        {
             foreach (var (source, sourcePorts) in _attempts)
                    {
                foreach (var (port, time) in sourcePorts)
                {
                    if (time < thresholdTime)
                    {
                        sourcePorts.TryRemove(port, out _);
                    }

                }
                         if (sourcePorts.IsEmpty)
                            {
                                _attempts.TryRemove(source, out _);
                            }
                    }
        }
    }
}