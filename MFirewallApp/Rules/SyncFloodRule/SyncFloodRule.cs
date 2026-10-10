using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.SyncFloodRule
{
    public class SyncFloodRule
    {
        public string RuleName => "sync_flood_rule";

        public int RuleScore => 100;
    }
}