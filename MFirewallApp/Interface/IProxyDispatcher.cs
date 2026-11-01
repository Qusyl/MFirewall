using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace MFirewallApp.Interface
{
    public interface IProxyDispatcher
    {
        Task DispatchAsync(TcpClient client, CancellationToken cancellationToken);
    }
}