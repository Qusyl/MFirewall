using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Interface
{
    public interface IIdentityService
    {
        Task<(bool IsSuccess, string UserId)> CreateUserAsync( string email, string passwordHash);

        Task<string> GetUserIdByEmail(string email);

        Task<string> GetUserPasswordHash(string email);

        Task<IList<string>> GetUserRoles(string userId);

        Task<bool> ConvocatRoleAsync(string userId, string role);
    }
}