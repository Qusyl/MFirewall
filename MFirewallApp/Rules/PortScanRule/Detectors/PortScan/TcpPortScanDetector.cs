
using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.FileSystem;
using MFirewallApp.Verdict;


namespace MFirewallApp.Rules.PortScanRule.Detectors.PortScan
{
    public class TcpPortScanDetector : PortScanDetector
    {
        public TcpPortScanDetector(ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>> attempts) : base(attempts)
        {
        }
        public override PacketDecision ShouldBlock(IPv4Packet packet, FirewallProtection configuration)
        {
            if (packet.ExtractPacket() is TcpPacket tcp)
            {
                if (!tcp.Header.IsSyn || tcp.Header.IsAck)
                {
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "packet is not syn or ack", "tcp port scan detector");
                }
                var packetSource = new PacketSource(packet.Header.SourceAddress, packet.Header.DestinationAddress, Protocol.TCP);

                var ports = _attempts.GetOrAdd(packetSource, _ => new ConcurrentDictionary<ushort, DateTimeOffset>());

                ports[tcp.Header.DestinationPort] = DateTimeOffset.UtcNow;

                var now = DateTimeOffset.UtcNow;

                var thresholdMaxCount = configuration.TcpPortScanOptions.UniquePacketsThreshold;

                var window = TimeSpan.FromSeconds(configuration.TcpPortScanOptions.WindowSeconds);

                var threshold = now - window;

                ClearExpiredPorts(threshold);

                var countPorts = _attempts[packetSource];
                FileLogger.AppendLogFile(
                $"[UDP_PORT_SCAN_DETECTOR]: " +
                $"Source={packet.Header.SourceAddress}, " +
                $"Destination={packet.Header.DestinationAddress}, " +
                $"Port={tcp.Header.DestinationPort}, " +
                $"UniquePorts={ports.Count}, " +
                $"Threshold={thresholdMaxCount}");
                if (countPorts.Count >= thresholdMaxCount)
                {
                   
                    FileLogger.AppendLogFile($"[TCP_PORT_SCAN_DETECTOR]: {Verdict.Verdict.DROP.ToString()} []");
                    return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"unique ports count exceeded [{countPorts.Count}]", "tcp port scan detector");
                }
                FileLogger.AppendLogFile($"[TCP_PORT_SCAN_DETECTOR]: {Verdict.Verdict.ACCEPT.ToString()}");
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "no reason for drop", "tcp port scan detector");
            }
           
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, "packet is not tcp", "tcp port scan detector");
        }
    }
}