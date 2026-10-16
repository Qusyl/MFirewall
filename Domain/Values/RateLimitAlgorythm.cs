using System.Text.Json.Serialization;

namespace Domain.Values
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RateLimitAlgorithm
    {
        FIXED_WINDOW,
        TOKEN_BUCKET
    }
}