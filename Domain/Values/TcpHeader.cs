using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Domain.Values
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TcpHeader
    {
        public ushort SourcePort;
        public ushort DestinationPort;
        public uint SequenceNumber;
        public uint AckNumber;

        private ushort dataOffsetAndFlags;

        public ushort WindowSize;
        public ushort CheckSum;

        public ushort UrgentPointer;

        public int dataOffset => (System.Net.IPAddress.NetworkToHostOrder((short)dataOffsetAndFlags) >> 12) & 0xF;
        public bool IsSyn => (System.Net.IPAddress.NetworkToHostOrder((short)dataOffsetAndFlags) & 0x0002) != 0;
        public bool IsAck => (System.Net.IPAddress.NetworkToHostOrder((short)dataOffsetAndFlags) & 0x0010) != 0;
        public bool IsFin => (System.Net.IPAddress.NetworkToHostOrder((short)dataOffsetAndFlags) & 0x0001) != 0;
    }
}