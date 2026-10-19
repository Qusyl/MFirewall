using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Analyse;
using MFirewallApp.Interface;
using Microsoft.AspNetCore.SignalR;

namespace MFirewallApp.Hubs
{
    public class LoggerHub : Hub<ILoggerClient>
    {
        
    }
}