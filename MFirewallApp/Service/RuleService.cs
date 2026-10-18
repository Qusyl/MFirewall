using System.Runtime.CompilerServices;
using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Rules;
using MFirewallApp.Verdict;
using Microsoft.Extensions.Options;

namespace MFirewallApp.Service
{
    public class RuleService : IRuleService
    {
        private IEnumerable<IPacketRule> _rules;

        private readonly IOptionsMonitor<FirewallConfiguration> _configurations;

        public RuleService(IEnumerable<IPacketRule> rules, IOptionsMonitor<FirewallConfiguration> optionsMonitor)
        {
            _rules = rules;
            _configurations = optionsMonitor;
        }
        public PacketDecision CheckRules(IPv4Packet packet)
        {
            var verdictResult = _configurations.CurrentValue.RuleStrategy switch
            {
                DropOrAcceptRuleStrategy.FIRST_MATCHING => WithFirstMatching(packet),
                DropOrAcceptRuleStrategy.SCORE_BASED => WithScoreBased(packet),
                _ => throw new SwitchExpressionException()
            };

            LOG($"Результат проверок: {verdictResult.ToString()}");
           
            return verdictResult;
        }

        private void LOG(string log)
        {
            FileLogger.AppendLogFile(log);
        }
        private PacketDecision WithFirstMatching(IPv4Packet packet)
        {
            if (packet is null)
            {
                return new PacketDecision(0,Verdict.Verdict.DROP, "Packet is null", "system");
            }
            var parameters = _configurations.CurrentValue.FirewallProtection;

            foreach (var rule in _rules)
            {

                var verdict = rule.Check(packet, parameters);

                if (verdict.Verdict is Verdict.Verdict.DROP)
                {
                    return verdict;
                }
            }
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "", "");
         
        }
        private PacketDecision WithScoreBased(IPv4Packet packet)
        {

            if (packet is null)
            {
                return new PacketDecision(0,Verdict.Verdict.DROP, "Packet is null", "system");
            }
            var score = 0;
            var parameters = _configurations.CurrentValue.FirewallProtection;
            foreach (var rule in _rules)
            {

                var verdict = rule.Check(packet,parameters );
                LOG($"[{rule.RuleName}]: {verdict.ToString()}");
                if (verdict.Verdict is Verdict.Verdict.DROP && rule.RuleScore >= 100)
                {
                    return verdict;
                }

                else if (verdict.Verdict is Verdict.Verdict.ACCEPT)
                {
                    score += rule.RuleScore;
                }
            }
            LOG($"Получено {score} баллов");
            if (score < 75)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, "Packet has not enough security score", "Score based strategy");
            }
            return  new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "", "");
        }
        } 
    
    }