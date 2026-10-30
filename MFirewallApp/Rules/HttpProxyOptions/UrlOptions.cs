using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.HttpProxyOptions
{
    public class UrlOptions
    {
        public List<string> NotAllowedQueryParameters { get; set; } = new();
    }
}