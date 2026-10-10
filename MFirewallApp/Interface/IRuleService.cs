
using Domain.Models.Packets;

namespace MFirewallApp.Interface
{
    public interface IRuleService
    {
        
        Verdict.Verdict CheckRules(IPv4Packet packet);
    }
}