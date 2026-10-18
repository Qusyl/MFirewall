using Domain.Values;

namespace MFirewallApp.Rules.StatefulRule
{
    public readonly record struct ConnectionKey(string SourceIp, ushort SourcePort, string DestionationIp, ushort DestinationPort, Protocol Protocol)
    {
        public ConnectionKey Reverse()
        {
            return new ConnectionKey(
                DestionationIp,
                DestinationPort,
                SourceIp,
                SourcePort,
                Protocol
            );
        }
    }
}