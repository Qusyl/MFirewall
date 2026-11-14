using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Dto;

namespace MFirewallApp.Interface
{
    public interface IAuthenticationService
    {
        Task<Result<AuthResponseDto,string>> RegisterAsync(UserRegistrationDto registerDto);
        Task<Result<AuthResponseDto,string>> LoginAsync(UserLoginDto loginDto);
    }
}