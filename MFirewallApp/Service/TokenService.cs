using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using MFirewallApp.Crypto.Sha256Hmac;
using MFirewallApp.Crypto.Token;
using MFirewallApp.Dto;
using MFirewallApp.Interface;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace MFirewallApp.Service
{
    public class TokenService : ITokenService
    {
        private readonly JwtOptions _jwtOptions;
        private readonly Sha256Hmac _sha256Hmac = new();
        public TokenService(IOptions<JwtOptions> options)
        {
            _jwtOptions = options.Value;
        }
        public string GenerateAccessToken(AuthDto dto)
        {
            var now = DateTimeOffset.UtcNow;

            var header = new Dictionary<string, object>()
            {
                ["alg"] = "HS256",
                ["typ"] = "JWT"
            };

            var payloads = new Dictionary<string, object>()
            {
                ["sub"] = dto.UserId,
                ["email"] = dto.Email,
                ["jti"] = Guid.NewGuid().ToString(),
                ["roles"] = dto.Roles.ToArray(),
                ["iss"] = _jwtOptions.Issuer,
                ["aud"] = _jwtOptions.Audience,
                ["nbf"] = now.ToUnixTimeSeconds(),
                ["exp"] = _jwtOptions.ExpirationTime
            };

            var header64base = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));
            var payloads64Base = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payloads));
            var singInput = $"{header64base}.{payloads64Base}";

            var keyBytes = Encoding.UTF8.GetBytes(_jwtOptions.Key);

            var signature = _sha256Hmac.HashData(Encoding.UTF8.GetBytes(singInput), keyBytes);
            var signature64Base = Base64UrlEncode(signature);

            return $"{singInput}.{signature64Base}";
        }
        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert
            .ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        }
    }
    
}