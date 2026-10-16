using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.RateLimitRule
{
    public sealed class TokenBucketState
    {
        public double Tokens { get; set; }

        public DateTimeOffset LastRefill { get; set; }

        public object SyncRoot { get; } = new();
    }
}