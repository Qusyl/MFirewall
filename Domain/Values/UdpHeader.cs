using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Domain.Values
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct UdpHeader
    {
        public ushort SourcePort;
        public ushort DestinationPort;
        public ushort Length;
        public ushort Checksum;

        public ushort SourcePortHost => (ushort)System.Net.IPAddress.NetworkToHostOrder((ushort)SourcePort);
        public ushort DestinationPortHost => (ushort)System.Net.IPAddress.NetworkToHostOrder((ushort)DestinationPort);
        public ushort LengthHost => (ushort)System.Net.IPAddress.NetworkToHostOrder((ushort)Length);
    }
}