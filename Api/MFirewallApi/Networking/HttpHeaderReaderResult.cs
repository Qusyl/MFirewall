using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApi.Networking
{
    public sealed record HttpHeaderReaderResult(byte[] HeaderBytes, byte[] RemainingBytes);
}