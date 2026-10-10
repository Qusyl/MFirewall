using Domain.Values;

namespace Domain.Models.Packets
{
    public class TcpPacket : Packet
    {
        public TcpHeader Header { get; set; }

        public byte[] Options { get; set; }

        public byte[] Payload { get; set; }

        public TcpPacket(ReadOnlySpan<byte> bytes) : base("Tcp")
        {
            Header = TcpHeader.Parse(bytes);
            int headerSize = Header.HeaderLengthInBytes;
        
            Options = bytes[20..headerSize].ToArray();
            Payload = bytes[headerSize..].ToArray();
        }
    }
}