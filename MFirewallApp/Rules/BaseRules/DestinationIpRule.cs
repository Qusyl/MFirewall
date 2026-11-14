using System.Net;
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

    public PacketDecision Check(IPv4Packet packet, FirewallProtection configuration)
{
    if (!configuration.DestinationIpOptions.Enable)
    {
        return new PacketDecision(
            packet.Header.Identification,
            Verdict.Verdict.NO_MATCH,
            "Not enabled",
            RuleName);
    }

    
    var networks = new List<IPNetwork>(configuration.DestinationIpOptions.DestinationAddress.Count);
    foreach (var s in configuration.DestinationIpOptions.DestinationAddress)
    {
        if (IPNetwork.TryParse(s, out var net))
            networks.Add(net);
        
    }

    
    var packetIp = packet.Header.DestinationAddress;

  
    foreach (var net in networks)
    {
        if (net.Contains(packetIp))
        {
            return new PacketDecision(
                packet.Header.Identification,
                Verdict.Verdict.DROP,
                $"IP matched {packetIp} in {net}",
                RuleName);
        }
    }

    return new PacketDecision(
        packet.Header.Identification,
        Verdict.Verdict.NO_MATCH,
        $"IP not matched [{string.Join(", ", networks)}][{packetIp}]",
        RuleName);
}
    }
}