
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
        public async Task<Result<AuthResponseDto,string>> LoginAsync(UserLoginDto loginDto)
        {
            var email = loginDto.Email;

            var password = loginDto.Password;

            var hashedPassword = await _userIdentityService.GetUserPasswordHash(email);

            if (string.IsNullOrEmpty(hashedPassword))
            {
                return Result<AuthResponseDto, string>.Failure("User not found");
            }

            bool IsCorrect = _passwordService.VerifyPassword(password, hashedPassword);

            if (IsCorrect)
            {
                var userId = await _userIdentityService.GetUserIdByEmail(email);
               
                var roles = await _userIdentityService.GetUserRoles(userId);
                var authDto = new AuthDto(userId, email, roles);
                var token = _tokenService.GenerateAccessToken(authDto);

                var userRoles = await _userIdentityService.GetUserRoles(userId);
                if (string.IsNullOrEmpty(token)){
                    return Result<AuthResponseDto, string>.Failure("[login] Token generation error");
                }
                return Result<AuthResponseDto, string>.Success(new AuthResponseDto(token, userRoles));
            }
            return Result<AuthResponseDto, string>.Failure("Invalid password or email");

        }

        public async Task<Result<AuthResponseDto,string>> RegisterAsync(UserRegistrationDto registerDto)
        {
            var email = registerDto.Email;

            var password = registerDto.Password;

            var hashedPassword = _passwordService.HashPassword(password);

            var result = await _userIdentityService.CreateUserAsync(email, hashedPassword);

            if (!result.IsSuccess)
            {
                return Result<AuthResponseDto, string>.Failure($"Error while create user : {result.Error!}");
            }
            var authDto = new AuthDto(result.Value!, email, new List<string>());
            var token = _tokenService.GenerateAccessToken(authDto);
            if (string.IsNullOrEmpty(token))
            {
                return Result<AuthResponseDto, string>.Failure("[registration] Token generation error");
            }
            var userRoles = await _userIdentityService.GetUserRoles(result.Value!);
            return Result<AuthResponseDto, string>.Success(new AuthResponseDto(token, userRoles));
        }
    }
}