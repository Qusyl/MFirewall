using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;

namespace MFirewallApp.Rules.BaseRules
{
    public class DestinationIpRule : IPacketRule
    {
        public string RuleName => "destination_ip_rule";

        public int RuleScore => 35;

        public Verdict.Verdict Check(IPv4Packet packet,RuleParameters configuration)
        {
            if (string.IsNullOrWhiteSpace(configuration.DestinationIpRule))
            {
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.NO_MATCH.ToString()}");
                return Verdict.Verdict.NO_MATCH;
            }

            if (configuration.DestinationIpRule == packet.Header.DestinationAddress.ToString())
            {
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.DROP.ToString()}");
                return Verdict.Verdict.DROP;
            }

            return Verdict.Verdict.ACCEPT;
            
          
        }
    }
}