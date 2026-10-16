using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Values;

namespace MFirewallApp.Rules.PortScanRule.Options
{
    public sealed class RateLimitOptions
    {
        public bool Enable { get; set; } = true;
        public RateLimitAlgorithm Algorithm { get; set; } = RateLimitAlgorithm.FIXED_WINDOW;

        public TokenBucketOptions TokenBucket { get; set; } = new();

        public RateLimitPolicyOptions Ip { get; set; } = new();

        public RateLimitPolicyOptions Port { get; set; } = new();

        public RateLimitPolicyOptions Protocol { get; set; } = new();
    }
}