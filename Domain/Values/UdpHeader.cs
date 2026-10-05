using System.Buffers.Binary;

namespace Domain.Values
{
    public readonly struct UdpHeader
    {
        public ushort SourcePort { get; }
        public ushort DestinationPort { get; }
        public ushort Length { get; }
        public ushort Checksum { get; }

        private UdpHeader(ushort sourcePort, ushort destinationPort, ushort length, ushort checksum)
        {
            SourcePort = sourcePort;
            DestinationPort = destinationPort;
            Length = length;
            Checksum = checksum;
        }

        public static UdpHeader Parse(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < 8)
                throw new ArgumentException(
                    $"UDP header requires >= 8 bytes",
                    nameof(bytes));

            return new UdpHeader(
                sourcePort:BinaryPrimitives.ReadUInt16BigEndian(bytes),
                destinationPort:BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]),
                length:BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]),
                checksum:BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]));
        }
    }
}