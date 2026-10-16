
using MFirewallApp.Rules.PortScanRule;
using MFirewallApp.Rules.PortScanRule.Options;

namespace MFirewallApp.Rules
{
    public sealed class FirewallProtection
    {
        public DestinationIpOptions DestinationIpOptions { get; set; } = new();

        public DestinationPortOptions DestinationPortOptions { get; set; } = new();

        public SourceIpOptions SourceIpOptions { get; set; } = new();

        public SourcePortOptions SourcePortOptions { get; set; } = new();

        public ProtocolOptions ProtocolOptions { get; set; } = new();

        public TcpPortScanOptions TcpPortScanOptions { get; set; } = new();

        public UdpPortScanOptions UdpPortScanOptions { get; set; } = new();
        public TcpSynFloodOptions TcpSynFloodOptions { get; set; } = new();

        public UdpFloodOptions UdpFloodOptions { get; set; } = new();

        public RateLimitOptions RateLimitOptions { get; set; } = new();
    }
}