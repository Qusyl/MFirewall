using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Dto;

namespace MFirewallApp.Interface
{
    public interface IAuthenticationService
    {
        Task<Result<string,string>> RegisterAsync(UserRegistrationDto registerDto);
        Task<Result<string,string>> LoginAsync(UserLoginDto loginDto);
    }
}