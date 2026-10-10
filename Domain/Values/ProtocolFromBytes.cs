using System.Text.Json.Serialization;

namespace Domain.Values
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ProtocolFromBytes : byte
    {
        TCP = 6,
        Icmp = 1,

        Udp = 17,

        None = 0
    }
}