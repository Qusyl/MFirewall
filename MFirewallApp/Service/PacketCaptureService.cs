using Domain.Values;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace MFirewallApp.Service
{
    public class PacketCaptureService : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly NFQueue.NFQueue nFQueue;
    
        public PacketCaptureService(IServiceScopeFactory factory)
        {
            nFQueue = new NFQueue.NFQueue();
            _scopeFactory = factory;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var nfQueueTask = nFQueue.OpenNfqueueAsync(stoppingToken);
            using var scope = _scopeFactory.CreateScope();
            var receiver = scope.ServiceProvider.GetRequiredService<IPacketCaptureReceiver>();
            var parser = scope.ServiceProvider.GetRequiredService<IPacketParser>();
            var ruleDision = scope.ServiceProvider.GetRequiredService<IRuleService>();
        
            while (!stoppingToken.IsCancellationRequested)
            {
               var rawPacket = await receiver.ReceiveAsync(nFQueue.Reader(), stoppingToken);
                try
                {
                        
                        var parsed = parser.Parse(rawPacket);
                        if(parsed is null)
                        {
                            throw new NullReferenceException("Packet state is null");
                        }
                        var verdict = ruleDision.CheckRules(parsed);
                        nFQueue.SetVerdict(verdict, rawPacket.ID);
            
                }
                catch (OperationCanceledException op)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Log(ex.Message);
                    if(rawPacket is not null)
                    {
                        nFQueue.SetVerdict(Verdict.Verdict.DROP, rawPacket.ID);
                    }
                }
            }
            await nfQueueTask;
        }
        private void Log(string log)
        {
            FileLogger.AppendLogFile(log);
        }
        
    }
}