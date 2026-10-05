using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using Microsoft.Extensions.Hosting;

namespace MFirewallApp.Service
{
    public class PacketCaptureService : BackgroundService
    {
        private readonly IPacketCaptureReceiver _receiver;

        private readonly NFQueue.NFQueue nFQueue;
    
        public PacketCaptureService(IPacketCaptureReceiver receiver)
        {
            _receiver = receiver;
            nFQueue = new NFQueue.NFQueue();
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var nfQueueTask = nFQueue.OpenNfqueueAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {

                var rawPacket = await _receiver.ReceiveAsync(nFQueue.Reader(), stoppingToken);

                FileLogger.AppendLogFile($"[{DateTime.UtcNow.ToString("dd-MM-yyyy")}]: получено {rawPacket.Data.Length}");
            }

            await nfQueueTask;
        }
    }
}