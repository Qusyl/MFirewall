

namespace MFirewallApp.Rules.StatefulRule
{
    public sealed class ConnectionState
    {
        public TcpConnectionStatus Status { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset LastActive { get; set; } = DateTimeOffset.UtcNow;

        public bool ClientFinSeen { get; set; } = false;

        public bool ServerFinSeen { get; set; } = false;

    }
}