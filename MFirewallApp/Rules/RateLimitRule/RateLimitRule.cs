using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.RateLimitRule
{
    public class RateLimitRule
    {
        public string RuleName => "rate_limit_rule";

        public int RuleScore => 100;
    }
}