using Domain.Values;

namespace Domain.Models.Packets
{
    public class IcmpPacket : Packet
    {
        public IcmpHeader Header { get; set; }
        public byte[] Payload { get; set; }
        public IcmpPacket(ReadOnlySpan<byte> bytes, uint Id) : base(Id)
        {
            Header = IcmpHeader.Parse(bytes);
        }
    }
}