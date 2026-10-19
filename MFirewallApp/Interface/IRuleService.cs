
using Domain.Models.Packets;
using MFirewallApp.Verdict;

namespace MFirewallApp.Interface
{
    public interface IRuleService
    {
        
        Task<PacketDecision> CheckRules(IPv4Packet packet);
    }
}