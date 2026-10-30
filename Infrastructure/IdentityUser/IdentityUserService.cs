using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MFirewallApp.Interface;
using Microsoft.AspNetCore.Identity;

namespace Infrastructure.IdentityUser
{
    public class IdentityUserService : IIdentityService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public IdentityUserService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
    
        public async Task<bool> ConvocatRoleAsync(string userId, string role)
        {
            var user =await  _userManager.FindByIdAsync(userId);
            if(user is null)
            {
                return false;
            }
            var roles = await _userManager.GetRolesAsync(user);
            if (roles.Contains(role))
            {
                await _userManager.RemoveFromRoleAsync(user, role);
                return true;
            }
            return false;
            
        }

        public async Task<(bool IsSuccess, string UserId)> CreateUserAsync( string email, string passwordHash)
        {
            var id = Guid.NewGuid()
            .ToString();
            var createdUser = await _userManager.CreateAsync(new ApplicationUser
            {
                Id = id,
                Email = email,
                PasswordHash = passwordHash
            });

            if (!createdUser.Succeeded)
            {
                return (false, id);
            }
            return (true, id);
        }

        public async Task<string> GetUserIdByEmail(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user is null)
            {
                return "";
            }

            var Id = await _userManager.GetUserIdAsync(user);

            return Id ?? "";
        }

        public async Task<string> GetUserPasswordHash(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user is null)
            {
                return "";
            }

            var passwordHash = user.PasswordHash;

            return passwordHash ?? ""; 
        }

        public async Task<IList<string>> GetUserRoles(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user is null)
            {
                return new List<string>();
            }
            var userRoles = await _userManager.GetRolesAsync(user);

            return userRoles ?? new List<string>();
        }

    }
}