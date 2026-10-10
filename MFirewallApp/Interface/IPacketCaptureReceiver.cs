using System.Threading.Channels;
using Domain.Values;
namespace MFirewallApp.Interface
{
    public interface IPacketCaptureReceiver
    {
        Task<CapturedPacket> ReceiveAsync(ChannelReader<CapturedPacket> Reader ,CancellationToken cts);
    }
}