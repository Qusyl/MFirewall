

namespace MFirewallApp.Rules.PortScanRule
{
    public sealed class UdpFloodOptions
    {
        public bool Enable { get; set; } = true;

        public int MaxPackets { get; set; } = 300;

        public int WindowSeconds { get; set; } = 3;
    }
}