using System.Text;
using MFirewallApp.Crypto.Sha256Hmac;

public class Sha256HmacTests
{
    private readonly Sha256Hmac _hmac = new();

    [Fact]
    public void Rfc4231_Case1()
    {
        var key = Enumerable.Repeat((byte)0x0b, 20).ToArray();
        var data = Encoding.ASCII.GetBytes("Hi There");

        var actual = _hmac.HashData(data, key);

        Assert.Equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                     Convert.ToHexString(actual).ToLowerInvariant());
    }

    [Fact]
    public void Rfc4231_Case2_ShortKey()
    {
        var actual = _hmac.HashData(
            Encoding.ASCII.GetBytes("what do ya want for nothing?"),
            Encoding.ASCII.GetBytes("Jefe"));

        Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                     Convert.ToHexString(actual).ToLowerInvariant());
    }

    [Fact]
    public void Rfc4231_Case6_KeyLongerThanBlock()
    {
        var key = Enumerable.Repeat((byte)0xaa, 131).ToArray();
        var data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");

        var actual = _hmac.HashData(data, key);

        Assert.Equal("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                     Convert.ToHexString(actual).ToLowerInvariant());
    }
}