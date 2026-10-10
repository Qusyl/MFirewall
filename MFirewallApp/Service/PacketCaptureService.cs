using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

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

            FileLogger.ClearLogFile();

           
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var nfQueueTask = nFQueue.OpenNfqueueAsync(stoppingToken);
            using var scope = _scopeFactory.CreateScope();
            var rules = scope.ServiceProvider.GetServices<IPacketRule>();
            foreach(var rule in rules)
            {
                Log(rule.RuleName);
            }
            var receiver = scope.ServiceProvider.GetRequiredService<IPacketCaptureReceiver>();
            var ruleDision = scope.ServiceProvider.GetRequiredService<IRuleService>();
        
            while (!stoppingToken.IsCancellationRequested)
            {
                var rawPacket = await receiver.ReceiveAsync(nFQueue.Reader(), stoppingToken);
                Log($"NFQueue: получен сырой пакет, ID={rawPacket.ID}, размер={rawPacket.Data.Length} байт");
                try
                {

                    var ipV4Packet = new IPv4Packet(rawPacket.Data);
                    Log($"[{nameof(PacketCaptureService)}]: Определение типа пакета...");
                 

                        var verdict = ruleDision.CheckRules(ipV4Packet);
                        
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