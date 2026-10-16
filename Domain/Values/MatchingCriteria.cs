using System.Text.Json.Serialization;

namespace Domain.Values
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum MatchingCriteria
    {
        IP,
        PORT,
        PROTOCOL,

        ALL,

        NONE
    }
}