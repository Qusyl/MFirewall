using System.Text.Json.Serialization;

namespace MFirewallApp.Rules
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum DropOrAcceptRuleStrategy
    {
        FIRST_MATCHING,
        SCORE_BASED
    }
}