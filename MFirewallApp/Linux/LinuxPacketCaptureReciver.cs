
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Domain.Values;
using MFirewallApp.Interface;
using Microsoft.Extensions.Hosting;

namespace MFirewallApp.Linux
{
    public class LinuxPacketCaptureReciver : IPacketCaptureReceiver
    {
        public async Task<CapturedPacket> ReceiveAsync(ChannelReader<CapturedPacket> Reader, CancellationToken cts)
        {
            return await Reader.ReadAsync(cts);
        }
    }
}