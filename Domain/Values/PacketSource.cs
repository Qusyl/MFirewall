using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Domain.Values
{
    public sealed class PacketSource(IPAddress source, IPAddress destination)
    {
        public IPAddress Source { get; } = source;

        public IPAddress Destination { get; } = destination;       
    }
}