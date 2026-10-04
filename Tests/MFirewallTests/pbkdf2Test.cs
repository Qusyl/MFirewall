using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using MFirewallApp.Crypto.Pbkdf2;

namespace MFirewallTests
{
    public class pbkdf2Test
    {
        private readonly Pbkdf2 _pbkdf2 = new Pbkdf2();
        [Theory]
        [InlineData(1, 32)]
        [InlineData(2, 32)]
        [InlineData(1000, 20)]
        [InlineData(10, 32)]
        [InlineData(10, 33)]
        [InlineData(10, 100)]
        public void Pbkdf2_MatchesDotNet(int iterations, int dkLen)
        {
            var password = Encoding.UTF8.GetBytes("пароль123");
            var salt = Encoding.UTF8.GetBytes("somesalt");

            var expected = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, dkLen);
            var actual = _pbkdf2.DeriveKey(password, salt, iterations, dkLen);


            Assert.Equal(expected, actual);
        }
    [Theory]
[InlineData(0)]
[InlineData(-1)]
public void Pbkdf2_InvalidIterations_Throws(int iterations)
{
    Assert.Throws<ArgumentOutOfRangeException>(() =>
        _pbkdf2.DeriveKey(new byte[] { 1 }, new byte[] { 2 }, iterations, 32));
}
}
}
