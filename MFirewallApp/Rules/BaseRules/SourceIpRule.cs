using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.BaseRules
{
    public class IpRule : IPacketRule
    {
        public string RuleName => "source_ip_rule";

        public int RuleScore => 35;

        public PacketDecision Check(IPv4Packet packet, FirewallProtection configuration)
        {
            if (!configuration.SourceIpOptions.Enable)
            {

       
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", RuleName);
            }

            var configIp = configuration.SourceIpOptions.SourceAddress;

            var packetIp = packet.Header.SourceAddress.ToString();
            if ( configIp==packetIp )
            {
              
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"SOURCE IP matched [{configIp}][{packetIp}]", RuleName);
            }
               
               return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, $"SOURCE IP not matched [{configIp}][{packetIp}]", RuleName);
            }
           
        }
    }
