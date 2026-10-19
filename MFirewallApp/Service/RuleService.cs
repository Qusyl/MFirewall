using System.Runtime.CompilerServices;
using Domain.Models.Packets;
using MFirewallApp.Analyse;
using MFirewallApp.FileSystem;
using MFirewallApp.Hubs;
using MFirewallApp.Interface;
using MFirewallApp.Rules;
using MFirewallApp.Verdict;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;

namespace MFirewallApp.Service
{
    public class RuleService : IRuleService
    {
        private IEnumerable<IPacketRule> _rules;

        private readonly IOptionsMonitor<FirewallConfiguration> _configurations;

        private readonly ReportQueue queueReport;
      

        public RuleService(IEnumerable<IPacketRule> rules, IOptionsMonitor<FirewallConfiguration> optionsMonitor, ReportQueue reportQ)
        {
            queueReport = reportQ;
            _rules = rules;
            _configurations = optionsMonitor;
        }
        public async Task<PacketDecision>  CheckRules(IPv4Packet packet)
        {
            var verdictResult = _configurations.CurrentValue.RuleStrategy switch
            {
                DropOrAcceptRuleStrategy.FIRST_MATCHING => await WithFirstMatching(packet),
                DropOrAcceptRuleStrategy.SCORE_BASED => await WithScoreBased(packet),
                _ => throw new SwitchExpressionException()
            };

            LOG($"Результат проверок: {verdictResult.ToString()}");
           
            return verdictResult;
        }

        private void LOG(string log)
        {
            FileLogger.AppendLogFile(log);
        }
        private async Task<PacketDecision> WithFirstMatching(IPv4Packet packet)
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
                    var report = new FirewallReport(DateTimeOffset.UtcNow, verdict);
                    queueReport.Equeue(report);
                    return verdict;
                }
            }
            
           
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "No reason for drop", "[RULE_SERVICE]");
         
        }
        private async Task<PacketDecision> WithScoreBased(IPv4Packet packet)
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
                if (verdict.Verdict is Verdict.Verdict.DROP && rule.RuleScore >= 100)
                {
                    var report = new FirewallReport(DateTimeOffset.UtcNow, verdict);
                     queueReport.Equeue(report);
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
                var decision = new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, $"Packet has not enough security score : {score}", "[RULE_SERVICE]");
                var report = new FirewallReport(DateTimeOffset.UtcNow, decision);
                 queueReport.Equeue(report);
                return decision;
            }
            return  new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "No reason for drop", "[RULE_SERVICE]");
        }
        } 
    
    }