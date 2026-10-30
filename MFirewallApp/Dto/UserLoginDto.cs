using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Dto
{
    public sealed record UserLoginDto(string Email, string Password);
}