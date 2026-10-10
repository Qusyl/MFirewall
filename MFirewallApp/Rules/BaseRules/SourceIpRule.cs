using Domain.Models.Packets;
using MFirewallApp.FileSystem;
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
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.NO_MATCH.ToString()}");
                 return Verdict.Verdict.NO_MATCH;
            }

            if (configuration.SourceIpRule == packet.Header.SourceAddress.ToString())
            {
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.DROP.ToString()}");
                return Verdict.Verdict.DROP;
            }
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.ACCEPT.ToString()}");
                return Verdict.Verdict.ACCEPT;
            }
           
        }
    }
