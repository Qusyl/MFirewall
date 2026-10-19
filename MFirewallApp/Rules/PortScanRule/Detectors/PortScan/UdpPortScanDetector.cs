using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.FileSystem;
using MFirewallApp.Verdict;
namespace MFirewallApp.Rules.PortScanRule.Detectors.PortScan
{
    public class UdpPortScanDetector : PortScanDetector
    {
        public UdpPortScanDetector(ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>> attempts) : base(attempts)
        {
            
        }
        public override PacketDecision ShouldBlock(IPv4Packet packet, FirewallProtection configuration)
        {
            if (packet.ExtractPacket() is UdpPacket udp)
            {
                var packetSource = new PacketSource(packet.Header.SourceAddress, packet.Header.DestinationAddress, Protocol.UDP);

                var ports = _attempts.GetOrAdd(packetSource, _ => new ConcurrentDictionary<ushort, DateTimeOffset>());

                ports[udp.Header.DestinationPort] = DateTimeOffset.UtcNow;

                DateTimeOffset now = DateTimeOffset.UtcNow;

                int portThreshold = configuration.UdpPortScanOptions.UniquePacketsThreshold;

                var window = TimeSpan.FromSeconds(configuration.UdpPortScanOptions.WindowSeconds);

                var synThreshold = now - window;

                ClearExpiredPorts(synThreshold);

                var countPorts = _attempts[packetSource];
                
                FileLogger.AppendLogFile(
                $"[UDP_PORT_SCAN_DETECTOR]: " +
                $"Source={packet.Header.SourceAddress}, " +
                $"Destination={packet.Header.DestinationAddress}, " +
                $"Port={udp.Header.DestinationPort}, " +
                $"UniquePorts={ports.Count}, " +
                $"Threshold={portThreshold}");
                if (countPorts.Count >= portThreshold)
                {
                    
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"unique ports count exceeded [{countPorts.Count}]", "udp port scan detector");
                }

               
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "no reason for drop", "udp port scan detector");

            }
            
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, "packet is not udp", "udp port scan detector");
        }
    }
}