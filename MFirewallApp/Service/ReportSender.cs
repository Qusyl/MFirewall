using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.FileSystem;
using MFirewallApp.Hubs;
using MFirewallApp.Interface;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Hosting;

namespace MFirewallApp.Service
{
    public class ReportSender : BackgroundService
    {
        private readonly IHubContext<LoggerHub, ILoggerClient> _hub;
        private readonly ReportQueue reportQueue;

        public ReportSender(IHubContext<LoggerHub, ILoggerClient> hub, ReportQueue queueReport)
        {
            _hub = hub;
            reportQueue = queueReport;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach(var report in reportQueue.ReadAllAsync(stoppingToken))
            {
                try
                {
                    await _hub.Clients.All.GetReport(report);
                }
                catch(Exception ex)
                {
                    FileLogger.AppendLogFile($"[ReportSender] {ex.Message}");
                }
            }
        }
    }
}