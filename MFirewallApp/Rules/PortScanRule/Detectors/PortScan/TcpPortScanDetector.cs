
using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.FileSystem;


namespace MFirewallApp.Rules.PortScanRule.Detectors.PortScan
{
    public class TcpPortScanDetector : PortScanDetector
    {
        public TcpPortScanDetector(ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>> attempts) : base(attempts)
        {
        }
        public override Verdict.Verdict ShouldBlock(IPv4Packet packet, FirewallProtection configuration)
        {
            if (packet.ExtractPacket() is TcpPacket tcp)
            {
                if (!tcp.Header.IsSyn || tcp.Header.IsAck)
                {
                    return Verdict.Verdict.NO_MATCH;
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

                if (countPorts.Count >= thresholdMaxCount)
                {
                   
                    FileLogger.AppendLogFile($"[TCP_PORT_SCAN_DETECTOR]: {Verdict.Verdict.DROP.ToString()} []");
                    return Verdict.Verdict.DROP;
                }
                FileLogger.AppendLogFile($"[TCP_PORT_SCAN_DETECTOR]: {Verdict.Verdict.ACCEPT.ToString()}");
                return Verdict.Verdict.ACCEPT;
            }
            FileLogger.AppendLogFile($"[TCP_PORT_SCAN_DETECTOR]: {Verdict.Verdict.NO_MATCH.ToString()}");
            return Verdict.Verdict.NO_MATCH;
        }
    }
}