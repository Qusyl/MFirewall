using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.BaseRules
{
    public class DestinationIpRule : IPacketRule
    {
        public string RuleName => "destination_ip_rule";

        public int RuleScore => 35;

        public PacketDecision Check(IPv4Packet packet,FirewallProtection configuration)
        {
            var configAddress = configuration.DestinationIpOptions.DestinationAddress;
            var packetAddress = packet.Header.DestinationAddress.ToString();
            if (!configuration.DestinationIpOptions.Enable)
            {
                
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not enabled", RuleName);
            }

            if (configAddress == packetAddress)
            {
                FileLogger.AppendLogFile($"[{RuleName}]: {Verdict.Verdict.DROP.ToString()}");
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"IP matched [{configAddress}][{packetAddress}]", RuleName);
            }

            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, $"IP not mached [{configAddress}][{packetAddress}]", RuleName);
        
        }
    }
}