using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Rules.HttpProxyOptions;

namespace MFirewallApp.Rules
{
    public class HttpProxyConfiguration
    {
        public AllowedDomainOptions AllowedDomainOptions { get; set; } = new();

        public BlackListDomainOptions BlackListDomainOptions { get; set; } = new();

        public UrlOptions UrlOptions { get; set; } = new();

        public HttpsOptions HttpsOptions { get; set; } = new();

    }
}