using MFirewallApp.Crypto.Sha256Hmac;

namespace MFirewallTests;

public class UnitTest1
{
    [Fact]
    public void sha256_working_not_out_of_index()
    {
        var sha256 = new Sha256();

        byte[] b2 = sha256.HashData(new string('a', 55));

        byte[] b3 = sha256.HashData(new string('a', 56));

        byte[] b4 = sha256.HashData(new string('a', 63));

        byte[] b5 = sha256.HashData(new string('a', 64));

        Assert.True(true);
    }
}
