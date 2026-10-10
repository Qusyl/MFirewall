using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Values;

namespace Domain.Models.Packets
{
    
    public class UdpPacket : Packet 
    {
        public UdpHeader Header { get; set; }

        public byte[] Payload { get; set; }

        public UdpPacket(ReadOnlySpan<byte> bytes) : base("Udp")
        {
            Header = UdpHeader.Parse(bytes);

            int headerSize = 8;

            Payload = bytes[headerSize..].ToArray();
        }
    }
}