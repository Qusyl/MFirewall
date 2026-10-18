using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Interface;
using MFirewallApp.Rules.PortScanRule.Detectors.PortScan;
using MFirewallApp.Verdict;


namespace MFirewallApp.Rules.PortScanRule
{
    public class PortScanRule : IPacketRule
    {
        private readonly ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>> _attempts;
        public PortScanRule()
        {
            _attempts = new ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>>();
        }
        public string RuleName => "port_scan_rule";

        public int RuleScore => 100;
        public PacketDecision Check(IPv4Packet packet, FirewallProtection configuration)
        {
            var detector = PortScanDetectorFactory.Create(packet, _attempts);

            if(detector is null)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, "Packet is null", RuleName);
            }

            return detector.ShouldBlock(packet, configuration);
        }
    }
}