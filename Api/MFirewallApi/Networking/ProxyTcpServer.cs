using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using MFirewallApp.Interface;

namespace MFirewallApi.Networking
{
    public class ProxyTcpServer : BackgroundService
    {
        private readonly ILogger<ProxyTcpServer> _logger;

        private readonly IServiceScopeFactory _scopeFactory;

        private TcpListener? _serverListener;

        public ProxyTcpServer(IServiceScopeFactory scopeFactory, ILogger<ProxyTcpServer> logger)
        {
            _scopeFactory = scopeFactory;
            _logger = logger;
        }
        protected async override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _serverListener = new TcpListener(IPAddress.Loopback, 5118);

            _serverListener.Start();

            _logger.LogInformation(
          "TCP Proxy started on port 5118");

            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    TcpClient client = await _serverListener.AcceptTcpClientAsync(stoppingToken);

                   await using var scope = _scopeFactory.CreateAsyncScope();

                    var dispatcher = scope.ServiceProvider.GetRequiredService<IProxyDispatcher>();

                    _ = HandleClientAsync(client,dispatcher,stoppingToken);
                }

            }
            catch (OperationCanceledException op)
            {
                _logger.LogInformation("Tcp proxy stopped");
            }
            catch (SocketException sockEx) when (stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("TCP Proxy stopped: {Message}", sockEx.Message);
            }
            finally
            {
                _serverListener.Stop();
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            
            return base.StopAsync(cancellationToken);
        }

        private async Task HandleClientAsync(TcpClient client, IProxyDispatcher proxyDispatcher,CancellationToken token)
        {
            using (client)
            {
                try
                {
                    await proxyDispatcher.DispatchAsync(client, token);
                }
                catch(Exception ex)
                {
                    _logger.LogError("Tcp client error : {0}", ex.Message);
                }
            }
        }
    }
}