
using Domain.Models.Packets;
using MFirewallApp.Verdict;

namespace MFirewallApp.Interface
{
    public interface IRuleService
    {
        
        PacketDecision CheckRules(IPv4Packet packet);
    }
}