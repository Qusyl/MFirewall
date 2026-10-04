using System.Text;
using MFirewallApp.Crypto.Sha256Hmac;
using Xunit;

public class Sha256Tests
{
    private readonly Sha256 _sha = new(); 

    [Theory]
    [InlineData("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    [InlineData("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
    public void HashData_KnownVectors(string input, string expectedHex)
    {
        var actual = _sha.HashData(Encoding.ASCII.GetBytes(input));

        Assert.Equal(expectedHex, Convert.ToHexString(actual).ToLowerInvariant());
    }

    [Fact]
    public void HashData_MillionA()
    {
        var input = Enumerable.Repeat((byte)'a', 1_000_000).ToArray();

        var actual = _sha.HashData(input);

        Assert.Equal("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                     Convert.ToHexString(actual).ToLowerInvariant());
    }
    [Fact]
public void Sha256_IsDeterministic()
{
    var data = new byte[] { 1, 2, 3 };
    Assert.Equal(_sha.HashData(data), _sha.HashData(data));
}

[Fact]
public void Sha256_DoesNotModifyInput()
{
    var data = new byte[] { 1, 2, 3, 4, 5 };
    var copy = (byte[])data.Clone();

    _sha.HashData(data);

    Assert.Equal(copy, data);
}

[Fact]
public void Sha256_OutputIs32Bytes()
{
    Assert.Equal(32, _sha.HashData(new byte[10]).Length);
}

    [Fact]
    public void Sha256_OneBitChange_ChangesHash()
    {
        var a = new byte[] { 1, 2, 3 };
        var b = new byte[] { 1, 2, 2 };

        Assert.NotEqual(_sha.HashData(a), _sha.HashData(b));
    }
[Theory]
[InlineData(0)] [InlineData(1)] [InlineData(55)] [InlineData(56)] [InlineData(57)]
[InlineData(63)] [InlineData(64)] [InlineData(65)]
[InlineData(119)] [InlineData(120)] [InlineData(128)]
public void Sha256_PaddingBoundaries(int length)
{
    var data = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();

    Assert.Equal(_sha.HashData(data), _sha.HashData(data));
}
}