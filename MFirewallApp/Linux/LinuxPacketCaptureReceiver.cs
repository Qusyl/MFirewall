
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Domain.Values;
using MFirewallApp.Interface;


namespace MFirewallApp.Linux
{
    public class LinuxPacketCaptureReceiver : IPacketCaptureReceiver
    {
        public async Task<CapturedPacket> ReceiveAsync(ChannelReader<CapturedPacket> Reader, CancellationToken cts)
        {
            return await Reader.ReadAsync(cts);
        }
    }
}