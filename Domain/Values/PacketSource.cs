using System.Net;
namespace Domain.Values
{
    public sealed record PacketSource(IPAddress Source, IPAddress Destination, Protocol Protocol);
}