namespace MFirewallApp.Rules
{
    public sealed class RuleConfiguration
    {
        public DropOrAcceptRuleStrategy RuleStrategy { get; set; }
        public RuleParameters Parameters { get; set; } = new();
    }
}