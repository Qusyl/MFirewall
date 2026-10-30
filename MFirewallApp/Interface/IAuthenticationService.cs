using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Dto;

namespace MFirewallApp.Interface
{
    public interface IAuthenticationService
    {
        Task<string> RegisterAsync(UserRegistrationDto registerDto);
        Task<string> LoginAsync(UserLoginDto loginDto);
    }
}