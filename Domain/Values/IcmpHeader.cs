using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Domain.Values
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IcmpHeader
    {
        public byte Type;
        public byte Code;

        public ushort Checksum;
        public uint RestOfHeader;

        public ushort PingIdentifier => (ushort)(RestOfHeader >> 16);
        public ushort PingSequenceNumber => (ushort)(RestOfHeader & 0xFFFF);
    }
}