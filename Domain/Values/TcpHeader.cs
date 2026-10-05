using System.Buffers.Binary;
using System.Runtime.InteropServices;


public struct TcpHeader
{
    public ushort SourcePort;
    public ushort DestinationPort;  
    public uint SequenceNumber;
    public uint AckNumber;
    public ushort WindowSize;
    public ushort CheckSum;
    public ushort UrgentPointer;
    public int DataOffset;
    public int HeaderLengthInBytes => DataOffset * 4;
    public bool IsSyn;
    public bool IsAck;
    public bool IsFin;

    public static TcpHeader Parse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 20)
        {
            throw new ArgumentException("TCP header too short");
        }


        ushort dataOffsetAndFlags = BinaryPrimitives.ReadUInt16BigEndian(buffer[12..]);
        int dataOffset = (dataOffsetAndFlags >> 12) & 0xF;

        return new TcpHeader
        {
            SourcePort = BinaryPrimitives.ReadUInt16BigEndian(buffer),
            DestinationPort = BinaryPrimitives.ReadUInt16BigEndian(buffer[2..]),
            SequenceNumber = BinaryPrimitives.ReadUInt32BigEndian(buffer[4..]),
            AckNumber = BinaryPrimitives.ReadUInt32BigEndian(buffer[8..]),
            DataOffset = dataOffset,
            WindowSize = BinaryPrimitives.ReadUInt16BigEndian(buffer[14..]),
            CheckSum = BinaryPrimitives.ReadUInt16BigEndian(buffer[16..]),
            UrgentPointer = BinaryPrimitives.ReadUInt16BigEndian(buffer[18..]),
            IsSyn = (dataOffsetAndFlags & 0x0002) != 0,
            IsAck = (dataOffsetAndFlags & 0x0010) != 0,
            IsFin = (dataOffsetAndFlags & 0x0001) != 0,
        };
    }
}