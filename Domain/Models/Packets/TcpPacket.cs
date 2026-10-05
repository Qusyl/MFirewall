using Domain.Values;

namespace Domain.Models.Packets
{
    public class TcpPacket : Packet
    {
        public TcpHeader Header { get; set; }

        public byte[] Options { get; set; }

        public byte[] Payload { get; set; }

        public TcpPacket(ReadOnlySpan<byte> bytes, int Id) : base(Id)
        {
            Header = TcpHeader.Parse(bytes);
        }
    }
}