using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Domain.Models.Packets
{
    public class IPv4Packet 
    {
        public Ipv4Header Header { get; set; }

        public IPv4Packet(ReadOnlySpan<byte> bytes)
        {
            Header = Ipv4Header.Parse(bytes);
        }

        public ReadOnlyMemory<byte> Payloads { get; set; }
        
        public Packet ExtractPacket(uint id)
        {
            Packet packet = Header.Protocol switch
            {
                6 => new TcpPacket(Payloads.Span,id),
                1 => new IcmpPacket(Payloads.Span,id),
                17 => new UdpPacket(Payloads.Span,id),
                _ => throw new SwitchExpressionException("Packet not defined")
            };

            return packet;
        }
    }
}