using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.HttpProxyOptions
{
    public class BlackListDomainOptions
    {
        public List<string> BlackList { get; set; } = new();
    }
}