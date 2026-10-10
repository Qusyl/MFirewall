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
        public ReadOnlyMemory<byte> Payload { get;  }

        public IPv4Packet(ReadOnlySpan<byte> bytes)
        {
            Header = Ipv4Header.Parse(bytes);

            int iHl = Ihl(bytes[0]);

            int IhlSize = iHl * 4;
            
            Payload = bytes[IhlSize..].ToArray();

        }

        

        public Packet ExtractPacket()
        {
            Packet packet = Header.Protocol switch
            {
                Values.ProtocolFromBytes.TCP => new TcpPacket(Payload.Span),
                Values.ProtocolFromBytes.Icmp => new IcmpPacket(Payload.Span),
                Values.ProtocolFromBytes.Udp => new UdpPacket(Payload.Span),
                _ => throw new SwitchExpressionException("Packet not defined")
            };

            return packet;
        }
        
        private int Ihl(byte firstByte)
        {
            return firstByte & 0x0F;
        }
    }
}