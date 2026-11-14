using System.Net;
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
                return new PacketDecision(
                    packet.Header.Identification,
                    Verdict.Verdict.NO_MATCH,
                    "Not enabled",
                    RuleName);
            }

           
            var networks = new List<IPNetwork>(configuration.SourceIpOptions.SourceAddress.Count);
            foreach (var s in configuration.SourceIpOptions.SourceAddress)
            {
                if (IPNetwork.TryParse(s, out var net))
                    networks.Add(net);
            }

        
            var packetIp = packet.Header.SourceAddress;

            
            foreach (var net in networks)
            {
                if (net.Contains(packetIp))
                {
                    return new PacketDecision(
                        packet.Header.Identification,
                        Verdict.Verdict.DROP,
                        $"SOURCE IP matched {packetIp} in {net}",
                        RuleName);
                }
            }

            return new PacketDecision(
                packet.Header.Identification,
                Verdict.Verdict.NO_MATCH,
                $"SOURCE IP not matched [{string.Join(", ", networks)}][{packetIp}]",
                RuleName);
        }
    }
}
           
    

