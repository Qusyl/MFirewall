

using Domain.Models.Packets;
using MFirewallApp.Rules;
using MFirewallApp.Verdict;

namespace MFirewallApp.Interface
{
    public interface IPacketProcessingService
    {
       Task<PacketDecision> ProcessAsync(IPv4Packet packet);
    }
}