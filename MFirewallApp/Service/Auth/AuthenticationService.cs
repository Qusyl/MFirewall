
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
        public async Task<Result<string,string>> LoginAsync(UserLoginDto loginDto)
        {
            var email = loginDto.Email;

            var password = loginDto.Password;

            var hashedPassword = await _userIdentityService.GetUserPasswordHash(email);

            if (string.IsNullOrEmpty(hashedPassword))
            {
                return Result<string, string>.Failure("User not found");
            }

            bool IsCorrect = _passwordService.VerifyPassword(password, hashedPassword);

            if (IsCorrect)
            {
                var userId = await _userIdentityService.GetUserIdByEmail(email);
               
                var roles = await _userIdentityService.GetUserRoles(userId);
                var authDto = new AuthDto(userId, email, roles);
                var token = _tokenService.GenerateAccessToken(authDto);
                if (string.IsNullOrEmpty(token)){
                    return Result<string, string>.Failure("[login] Token generation error");
                }
                return Result<string, string>.Success(token);
            }
            return Result<string, string>.Failure("Invalid password or email");

        }

        public async Task<Result<string,string>> RegisterAsync(UserRegistrationDto registerDto)
        {
            var email = registerDto.Email;

            var password = registerDto.Password;

            var hashedPassword = _passwordService.HashPassword(password);

            var result = await _userIdentityService.CreateUserAsync(email, hashedPassword);

            if (!result.IsSuccess)
            {
                return Result<string, string>.Failure($"Error while create user : {result.Error!}");
            }
            var authDto = new AuthDto(result.Value!, email, new List<string>());
            var token = _tokenService.GenerateAccessToken(authDto);
             if (string.IsNullOrEmpty(token)){
                    return Result<string, string>.Failure("[registration] Token generation error");
                }
            return Result<string, string>.Success(token);
        }
    }
}