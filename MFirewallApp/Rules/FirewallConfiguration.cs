namespace MFirewallApp.Rules
{
    public sealed class FirewallConfiguration
    {
        public DropOrAcceptRuleStrategy RuleStrategy { get; set; }
        public FirewallProtection FirewallProtection { get; set; } = new();
    }
}