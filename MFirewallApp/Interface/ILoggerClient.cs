using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Analyse;

namespace MFirewallApp.Interface
{
    public interface ILoggerClient
    {
        Task GetReport(FirewallReport report);
        Task GetConnections(ConnectionSnapshot snapshot);
    }
}