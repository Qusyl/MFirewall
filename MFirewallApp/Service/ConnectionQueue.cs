using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using MFirewallApp.Analyse;

namespace MFirewallApp.Service
{
    public class ConnectionQueue
    {
         private readonly Channel<ConnectionSnapshot> _channel = Channel.CreateBounded<ConnectionSnapshot>(new BoundedChannelOptions(1024)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true
        });

        public void Equeue(ConnectionSnapshot snapshop) => _channel.Writer.TryWrite(snapshop);

        public  IAsyncEnumerable<ConnectionSnapshot> ReadAllAsync( CancellationToken cts) => _channel.Reader.ReadAllAsync(cts);
    }
}