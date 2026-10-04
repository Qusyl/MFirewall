using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models;

namespace MFirewallApp.Interface
{
    public interface IPacketIntersector
    {
        Task StartAsync(CancellationToken cts);
        event Action<RawPacket> PacketRecived;
        void Accept(RawPacket packet);

        void Drop(RawPacket packet);
    }
}