using Domain.Values;

namespace Domain.Models.Packets
{
    public class IcmpPacket : Packet
    {
        public IcmpHeader Header { get; set; }
        public byte[] Payload { get; set; }
    }
}