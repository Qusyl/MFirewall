using System.Runtime.CompilerServices;
using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Rules;
using Microsoft.Extensions.Options;

namespace MFirewallApp.Service
{
    public class RuleService : IRuleService
    {
        private IEnumerable<IPacketRule> _rules;

        private readonly IOptionsMonitor<RuleConfiguration> _configurations;

        public RuleService(IEnumerable<IPacketRule> rules, IOptionsMonitor<RuleConfiguration> optionsMonitor)
        {
            _rules = rules;
            _configurations = optionsMonitor;
        }
        public Verdict.Verdict CheckRules(IPv4Packet packet)
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
        private Verdict.Verdict WithFirstMatching(IPv4Packet packet)
        {
            if (packet is null)
            {
                return Verdict.Verdict.DROP;
            }
            var parameters = _configurations.CurrentValue.Parameters;
            foreach (var rule in _rules)
            {

                var verdict = rule.Check(packet, parameters);
                    
           
                if (verdict is Verdict.Verdict.DROP)
                {
                        return Verdict.Verdict.DROP;
                }
                
            }
            return Verdict.Verdict.ACCEPT;
        }
        private Verdict.Verdict WithScoreBased(IPv4Packet packet)
        {

            if (packet is null)
            {
                return Verdict.Verdict.DROP;
            }
            var score = 0;
            var parameters = _configurations.CurrentValue.Parameters;
            foreach (var rule in _rules)
            {

                var verdict = rule.Check(packet,parameters );
                LOG($"[{rule.RuleName}]: {verdict.ToString()}");
                if (verdict is Verdict.Verdict.DROP && rule.RuleScore >= 100)
                {
                    return Verdict.Verdict.DROP;
                }

                else if (verdict is Verdict.Verdict.ACCEPT)
                {
                    score += rule.RuleScore;
                }


            }
            LOG($"Получено {score} баллов");
            if (score < 75)
            {
                return Verdict.Verdict.DROP;
            }
            return Verdict.Verdict.ACCEPT;
        }
        
        } 
    
    }