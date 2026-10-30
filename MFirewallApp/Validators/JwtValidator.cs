using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using MFirewallApp.Crypto.Sha256Hmac;
using MFirewallApp.Crypto.Token;
using Microsoft.Extensions.Options;

namespace MFirewallApp.Validators
{
    public class JwtValidator
    {
        private readonly Sha256Hmac _sha256Hmac = new();
        private readonly JwtOptions _jwtOptions;

        public JwtValidator(IOptions<JwtOptions> options)
        {
            _jwtOptions = options.Value;
        }

        public bool TryValidate(string token, out JsonElement payload)
        {
            payload = default;

            var jwtParts = token.Split('.');
            if (jwtParts.Length != 3)
            {
                return false;
            }
            var signingInput = $"{jwtParts[0]}.{jwtParts[1]}";

            var keyBytes = Encoding.UTF8.GetBytes(_jwtOptions.Key);

            var expectedHash = _sha256Hmac.HashData(Encoding.UTF8.GetBytes(signingInput), keyBytes);
            var actualHash = Base64Decode(jwtParts[2]);

            if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
            {
                return false;
            }

            var payloadBytes = Base64Decode(jwtParts[1]);

            payload = JsonDocument.Parse(payloadBytes).RootElement;

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (payload.TryGetProperty("exp", out var exp) && exp.GetInt64() < now)
            {
                return false;
            }
            if(payload.TryGetProperty("nbf",out var nbf) && nbf.GetInt64() > now)
            {
                return false;
            }
            if (payload.TryGetProperty("iss", out var issuer) && issuer.GetString() != _jwtOptions.Issuer)
            {
                return false;
            }
            if (payload.TryGetProperty("aud", out var audience) && audience.GetString() != _jwtOptions.Audience)
            {
                return false;
            }
            return true;
        }
        
        private static byte[] Base64Decode(string base64)
        {
            base64 = base64
            .Replace('-', '+')
            .Replace('_', '/');

            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }
}