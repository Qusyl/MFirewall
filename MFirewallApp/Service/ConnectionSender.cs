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
    public class ConnectionSender : BackgroundService
    {
        private readonly IHubContext<LoggerHub, ILoggerClient> _hub;
        private readonly ConnectionQueue _connectionQueue;

        public ConnectionSender(IHubContext<LoggerHub, ILoggerClient> hub, ConnectionQueue connectionQueue)
        {
            _hub = hub;
            _connectionQueue = connectionQueue;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach(var connection in _connectionQueue.ReadAllAsync(stoppingToken))
            {
                try
                {
                    await _hub.Clients.All.GetConnections(connection);
                }
                catch(Exception ex)
                {
                    FileLogger.AppendLogFile($"[ReportSender] {ex.Message}");
                }
            }
        }
    }
}