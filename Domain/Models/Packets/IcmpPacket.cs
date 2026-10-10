using Domain.Values;

namespace Domain.Models.Packets
{
    public class IcmpPacket : Packet
    {
        public IcmpHeader Header { get; set; }
        public byte[] Payload { get; set; }

        public IcmpPacket(ReadOnlySpan<byte> bytes) : base("Icmp")
        {
            Header = IcmpHeader.Parse(bytes);
            int headerSize = 8;
            Payload = bytes[headerSize..].ToArray();
        }
    }
}