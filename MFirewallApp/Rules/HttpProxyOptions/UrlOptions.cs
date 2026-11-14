using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.HttpProxyOptions
{
    public class UrlOptions
    {
        public ObservableCollection<string> NotAllowedQueryParameters { get; set; } = new();

        public ObservableCollection<string> NotAllowedKeyWords { get; set; } = new();
        public ObservableCollection<string> BlockedExtensions { get; set; } = new();
    }
}