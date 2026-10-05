using System.Buffers.Binary;
using System.Net;

public struct Ipv4Header
{
    public byte Version;
    public byte Ihl;
    public int HeaderLengthInBytes => Ihl * 4;
    public byte TypeOfService;
    public ushort TotalLength;
    public ushort Identification;
    public bool DontFragment;
    public bool MoreFragments;
    public ushort FragmentOffset;
    public byte TimeToLive;
    public byte Protocol;
    public ushort HeaderChecksum;
    public IPAddress SourceAddress;
    public IPAddress DestinationAddress;

    public static Ipv4Header Parse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 20)
            throw new ArgumentException("IPv4 header too short");

        byte versionAndIhl = buffer[0];
        byte version = (byte)(versionAndIhl >> 4);
        byte ihl = (byte)(versionAndIhl & 0x0F);

        ushort totalLength = BinaryPrimitives.ReadUInt16BigEndian(buffer[2..]);
        ushort identification = BinaryPrimitives.ReadUInt16BigEndian(buffer[4..]);
        ushort flagsAndOffset = BinaryPrimitives.ReadUInt16BigEndian(buffer[6..]);

        return new Ipv4Header
        {
            Version = version,
            Ihl = ihl,
            TypeOfService = buffer[1],
            TotalLength = totalLength,
            Identification = identification,
            DontFragment = (flagsAndOffset & 0x4000) != 0,
            MoreFragments = (flagsAndOffset & 0x2000) != 0,
            FragmentOffset = (ushort)(flagsAndOffset & 0x1FFF),
            TimeToLive = buffer[8],
            Protocol = buffer[9],
            HeaderChecksum = BinaryPrimitives.ReadUInt16BigEndian(buffer[10..]),
            SourceAddress = new IPAddress(buffer.Slice(12, 4)),
            DestinationAddress = new IPAddress(buffer.Slice(16, 4)),
        };
    }
}