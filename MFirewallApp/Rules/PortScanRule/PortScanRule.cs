using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;


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

        private void ClearExpiredPorts(DateTimeOffset thresholdTime)
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

        public Verdict.Verdict Check(IPv4Packet packet,RuleParameters configuration)
        {
            if (packet.ExtractPacket() is TcpPacket tcp)
            {
                if (!tcp.Header.IsSyn || tcp.Header.IsAck)
                {
                    return Verdict.Verdict.NO_MATCH;
                }
                var packetSource = new PacketSource(packet.Header.SourceAddress, packet.Header.DestinationAddress);

                var ports = _attempts.GetOrAdd(packetSource, _ => new ConcurrentDictionary<ushort, DateTimeOffset>());

                ports[tcp.Header.DestinationPort] = DateTimeOffset.UtcNow;

                var now = DateTimeOffset.UtcNow;

                var thresholdMaxCount = configuration.UniquePortsThreshold;

                var window = TimeSpan.FromSeconds(configuration.SynWindow);

                var threshold = now - window;

                ClearExpiredPorts(threshold);

                var countPorts = _attempts[packetSource];

                if (countPorts.Count >= thresholdMaxCount)
                {
                    FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.DROP.ToString()}");
                    return Verdict.Verdict.DROP;
                }
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.ACCEPT.ToString()}");
                return Verdict.Verdict.ACCEPT;
            }
            FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.NO_MATCH.ToString()}");
               return Verdict.Verdict.NO_MATCH;
        }
    }
}