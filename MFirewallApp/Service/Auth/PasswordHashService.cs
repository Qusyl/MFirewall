using System.Security.Cryptography;
using System.Text;
using MFirewallApp.Crypto.Pbkdf2;
using MFirewallApp.Interface;

namespace MFirewallApp.Service.Auth
{
    public class PasswordHashService : IPasswordHasher
    {
        private const int SaltSize = 16;
        private const int KeySize = 32;

        private const int Iterations = 600_000;

        private static readonly Pbkdf2 pbkdf2 = new();
        public string HashPassword(string password)
        {

            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var saltBytes = RandomNumberGenerator.GetBytes(SaltSize);
            var hashed = pbkdf2.DeriveKey(passwordBytes, saltBytes, Iterations, KeySize);
            byte[] resultPassword = new byte[SaltSize + KeySize];
            Buffer.BlockCopy(saltBytes, 0, resultPassword, 0, SaltSize);
            Buffer.BlockCopy(hashed, 0, resultPassword, SaltSize, KeySize);
            return Convert.ToBase64String(resultPassword);
        }

        public bool VerifyPassword(string password, string storedHashWithSalt)
        {
            var decodeSaltKeyPair = Convert.FromBase64String(storedHashWithSalt);
            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(decodeSaltKeyPair, 0, salt, 0, SaltSize);
            byte[] originalHash = new byte[KeySize];
            Buffer.BlockCopy(decodeSaltKeyPair, SaltSize, originalHash, 0, KeySize);

            var passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] verifyHash = pbkdf2.DeriveKey(passwordBytes, salt, Iterations, KeySize);

            return CryptographicOperations.FixedTimeEquals(originalHash, verifyHash);
        }
    }
}