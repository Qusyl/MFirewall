using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Domain.Models;
using Domain.Values;

namespace MFirewallApp.Interface
{
    public interface IPacketCaptureReceiver
    {
        Task<CapturedPacket> ReceiveAsync(ChannelReader<CapturedPacket> Reader ,CancellationToken cts);
    }
}