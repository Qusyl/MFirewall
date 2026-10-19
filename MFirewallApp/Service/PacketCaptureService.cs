using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Analyse;
using MFirewallApp.FileSystem;
using MFirewallApp.Hubs;
using MFirewallApp.Interface;
using Microsoft.AspNetCore.SignalR;
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
            var rules = scope.ServiceProvider.GetServices<IPacketRule>();


           
            var receiver = scope.ServiceProvider.GetRequiredService<IPacketCaptureReceiver>();

            var packetProcessor = scope.ServiceProvider.GetRequiredService<IPacketProcessingService>();
        
            while (!stoppingToken.IsCancellationRequested)
            {
                FileLogger.CheckMemorySizeLimit(50);
                var rawPacket = await receiver.ReceiveAsync(nFQueue.Reader(), stoppingToken);
                Log($"NFQueue: получен сырой пакет, ID={rawPacket.ID}, размер={rawPacket.Data.Length} байт");
                try
                {
                    var ipV4Packet = new IPv4Packet(rawPacket.Data);
                    Log($"[{nameof(PacketCaptureService)}]: ТИП: {ipV4Packet.ExtractPacket().PacketType}");


                    var verdict =  await packetProcessor.ProcessAsync(ipV4Packet);

                    var report = new FirewallReport(
                        DateTimeOffset.UtcNow,
                        verdict);

                    
                        
                        nFQueue.SetVerdict(verdict.Verdict, rawPacket.ID);
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