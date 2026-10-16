
using System.Collections.Concurrent;

using Domain.Models.Packets;
using Domain.Values;


namespace MFirewallApp.Rules.PortScanRule.Detectors.PortScan
{
    public static class PortScanDetectorFactory
    {
        public static PortScanDetector? Create(IPv4Packet packet, ConcurrentDictionary<PacketSource, ConcurrentDictionary<ushort, DateTimeOffset>> attempts)
        {
            return packet.ExtractPacket() switch
            {
                TcpPacket tcp => new TcpPortScanDetector(attempts),
                UdpPacket udp => new UdpPortScanDetector(attempts),
                _ => default
            };
        }
        
    }
}