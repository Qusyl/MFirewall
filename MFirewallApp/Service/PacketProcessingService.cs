using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Hubs;
using MFirewallApp.Interface;
using MFirewallApp.Rules;
using MFirewallApp.Verdict;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;

namespace MFirewallApp.Service
{
    public class PacketProcessingService : IPacketProcessingService
    {
        private readonly IConnectionTracker _tracker;

        private readonly IRuleService _ruleService;

        public PacketProcessingService(IConnectionTracker tracker, IRuleService ruleService)
        {
          
            _tracker = tracker;
            _ruleService = ruleService;
        }
        public async Task<PacketDecision> ProcessAsync(IPv4Packet packet)
{
        var ruleDecision =await _ruleService.CheckRules(packet);
    
        var trackerDecision =await _tracker.ProcessConnectionAsync(packet);

            
            if (ruleDecision.Verdict is Verdict.Verdict.DROP)
            {
                return ruleDecision;
            }
            if (trackerDecision.Verdict is Verdict.Verdict.DROP)
            {
                return trackerDecision;
            }
            if (ruleDecision.Verdict is Verdict.Verdict.ACCEPT)
            {
                return ruleDecision;
            }
            if(trackerDecision.Verdict is Verdict.Verdict.ACCEPT)
            {
                return trackerDecision;
            }
    
    return ruleDecision;                      
}
    }
}