namespace MFirewallApp.Rules.PortScanRule.Options
{
    public sealed class TokenBucketOptions
    {
        public bool Enable { get; set; } = false;

        public double Capacity { get; set; } = 100;

        public double TokenPerSeconds { get; set; } = 50;

        public double TokenPerPacket { get; set; } = 5;
    }
}