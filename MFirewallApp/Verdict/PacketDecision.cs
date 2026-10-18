
namespace MFirewallApp.Verdict
{
    public sealed record PacketDecision(
            uint PacketQueueId,
            Verdict Verdict,
            string? Reason,
            string? MatchedRule
    );
}