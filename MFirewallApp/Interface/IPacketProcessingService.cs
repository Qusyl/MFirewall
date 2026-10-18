

using Domain.Models.Packets;
using MFirewallApp.Rules;
using MFirewallApp.Verdict;

namespace MFirewallApp.Interface
{
    public interface IPacketProcessingService
    {
        PacketDecision Process(IPv4Packet packet);
    }
}