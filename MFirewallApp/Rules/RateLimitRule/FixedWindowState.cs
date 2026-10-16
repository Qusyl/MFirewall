namespace MFirewallApp.Rules.RateLimitRule
{
    public class FixedWindowState
    {
        public DateTimeOffset WindowStart { get; set; } = DateTimeOffset.UtcNow;

        public int PacketCount { get; set; } = 0;
        public object syncRoot = new();
    }
}