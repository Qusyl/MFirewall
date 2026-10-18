using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models.Packets;
using MFirewallApp.Verdict;

namespace MFirewallApp.Interface
{
    public interface IConnectionTracker
    {
        public PacketDecision ProcessConnection(IPv4Packet packet);

        public int CleanupExpiredConnections(TimeSpan timeout);

    }
}