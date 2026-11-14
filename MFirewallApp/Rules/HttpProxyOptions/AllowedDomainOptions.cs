using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.HttpProxyOptions
{
    public class AllowedDomainOptions
    {
        public ObservableCollection<string> AllowedDomains { get; set; } = new() { "*" };
    }
}