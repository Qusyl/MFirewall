using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Dto
{
    public sealed record AuthDto(
        string UserId,
        string Email,
        string Password,
        IEnumerable<string> Roles);
}