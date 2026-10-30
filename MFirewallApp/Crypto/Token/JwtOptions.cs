using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Crypto.Token
{
    public class JwtOptions
    {
        public const string SectionName = "Jwt";

        [Required, MinLength(32)]
        public string Key { get; init; } = "";

        [Required]
        public string Issuer { get; init; } = "";

        [Required]
        public string Audience { get; init; } = "";

        [Range(1, 15)]
        public int ExpirationTime { get; init; } = 15;

    }
}