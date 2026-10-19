using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using System.Threading.Tasks;
using MFirewallApp.Analyse;

namespace MFirewallApp.Service
{
    public class ReportQueue
    {
        private readonly Channel<FirewallReport> _channel = Channel.CreateBounded<FirewallReport>(new BoundedChannelOptions(1024)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true
        });

        public void Equeue(FirewallReport report) => _channel.Writer.TryWrite(report);

        public  IAsyncEnumerable<FirewallReport> ReadAllAsync( CancellationToken cts) => _channel.Reader.ReadAllAsync(cts);
      

    }
}