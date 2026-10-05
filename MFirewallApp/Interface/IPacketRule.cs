using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models;
using Domain.Values;

namespace MFirewallApp.Interface
{
    public interface IPacketRule
    {
        Verdict.Verdict Check(Packet packet);
    }
}