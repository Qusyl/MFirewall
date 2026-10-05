using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Models;

namespace MFirewallApp.Interface
{
    public interface IRuleService
    {
        Verdict.Verdict CheckRules(Packet? packet);
    }
}