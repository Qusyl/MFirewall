using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models;
using MFirewallApp.Interface;

namespace MFirewallApp.Service
{
    public class RuleService : IRuleService
    {
        private IEnumerable<IPacketRule> _rules;
        public RuleService(IEnumerable<IPacketRule> rules)
        {
            _rules = rules;
        }
        public Verdict.Verdict CheckRules(Packet? packet)
        {
            if (packet is null)
            {
                return Verdict.Verdict.DROP;
            }
            
            foreach (var rule in _rules)
            {
                var verdict = rule.Check(packet);
                if (verdict is not Verdict.Verdict.NO_MATCH)
                {
                    return verdict;
                }
            }
            return Verdict.Verdict.DROP;
        }
    }
}