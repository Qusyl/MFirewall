
using MFirewallApp.Dto;
using MFirewallApp.Interface;


namespace MFirewallApp.Service.Auth
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IIdentityService _userIdentityService;

        private readonly IPasswordHasher _passwordService;

        private readonly ITokenService _tokenService;

        public AuthenticationService(IIdentityService identityService, IPasswordHasher passwordService, ITokenService tokenService)
        {
            _userIdentityService = identityService;
            _passwordService = passwordService;
            _tokenService = tokenService;
        }
        public async Task<string> LoginAsync(UserLoginDto loginDto)
        {
            var email = loginDto.Email;

            var password = loginDto.Password;

            var hashedPassword = await _userIdentityService.GetUserPasswordHash(email);

            if (string.IsNullOrEmpty(hashedPassword))
            {
                return "";
            }

            bool IsCorrect = _passwordService.VerifyPassword(password, hashedPassword);

            if (IsCorrect)
            {
                var userId = await _userIdentityService.GetUserIdByEmail(email);
                if (string.IsNullOrEmpty(userId))
                {
                    return "";
                }
                var roles = await _userIdentityService.GetUserRoles(userId);
                var authDto = new AuthDto(userId, email, password, roles);
                var token = _tokenService.GenerateAccessToken(authDto);
                return token ?? "";
            }
            return "";

        }

        public async Task<string> RegisterAsync(UserRegistrationDto registerDto)
        {
            var email = registerDto.Email;

            var password = registerDto.Password;

            var hashedPassword = _passwordService.HashPassword(password);

            var result = await _userIdentityService.CreateUserAsync(email, hashedPassword);

            if (!result.IsSuccess)
            {
                return "";
            }
            var authDto = new AuthDto(result.UserId, email, hashedPassword, new List<string>());
            var token = _tokenService.GenerateAccessToken(authDto);

            return token ?? "";
        }
    }
}