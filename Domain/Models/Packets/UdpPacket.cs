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

        public UdpPacket(ReadOnlySpan<byte> bytes, int Id) : base(Id)
        {
            Header = UdpHeader.Parse(bytes);
        }
    }
}