using Domain.Models;
using MFirewallApp.Interface;

namespace Infrastructure.Linux
{
    public class LinuxPacketInterceptor : IPacketIntersector
    {
        public event Action<RawPacket> PacketRecived;

        public void Accept(RawPacket packet)
        {
            throw new NotImplementedException();
        }

        public void Drop(RawPacket packet)
        {
            throw new NotImplementedException();
        }

        public Task StartAsync(CancellationToken cts)
        {
            throw new NotImplementedException();
        }
    }
}