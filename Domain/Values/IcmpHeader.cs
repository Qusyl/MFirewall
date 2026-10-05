using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace Domain.Values
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IcmpHeader
    {
        public byte Type;
        public byte Code;
        public ushort Checksum;
        public uint RestOfHeader;

        private uint RestOfHeaderHost => (uint)IPAddress.NetworkToHostOrder((int)RestOfHeader);

        public ushort EchoIdentifier => (ushort)(RestOfHeaderHost >> 16);
        public ushort EchoSequence   => (ushort)(RestOfHeaderHost & 0xFFFF);
        public ushort ChecksumNetwork => Checksum;
        public bool IsEchoRequest => Type == 8;
        public bool IsEchoReply => Type == 0;
        
        public static IcmpHeader Parse(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < 8)
            {
                throw new ArgumentException("ICMP header too short");
            }

            return new IcmpHeader
            {
                Type = buffer[0],
                Code = buffer[1],
                Checksum = BinaryPrimitives.ReadUInt16BigEndian(buffer[2..]),
                RestOfHeader = BinaryPrimitives.ReadUInt16BigEndian(buffer[4..])
            };
        }
    }
}