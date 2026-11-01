using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using MFirewallApp.Crypto.Token;
using MFirewallApp.Rules;
using Microsoft.Extensions.Options;

namespace MFirewallApp.Interface
{
    public interface ITunelHandler
    {
        Task HandleClientAsync(
            TcpClient client,
            string headerText,
            byte[] remainingBytes,
           CancellationToken cancellationToken);
    }
}