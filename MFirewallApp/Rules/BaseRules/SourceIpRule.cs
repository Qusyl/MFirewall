using Domain.Models.Packets;
using MFirewallApp.Interface;

namespace MFirewallApp.Rules.BaseRules
{
    public class IpRule : IPacketRule
    {
        public string RuleName => "source_ip_rule";

        public int RuleScore => 35;

        public Verdict.Verdict Check(IPv4Packet packet, RuleParameters configuration)
        {
            if (string.IsNullOrWhiteSpace(configuration.SourceIpRule))
            {
                 return Verdict.Verdict.NO_MATCH;
            }
        
                if (configuration.SourceIpRule == packet.Header.SourceAddress.ToString())
                {
                    return Verdict.Verdict.DROP;
                }
                return Verdict.Verdict.ACCEPT;
            }
           
        }
    }
