namespace MFirewallApp.Crypto.Pbkdf2
{
    public class Pbkdf2
    {
        private const int HLen = 32; 

        private Sha256Hmac.Sha256Hmac _sha256Hmac = new Sha256Hmac.Sha256Hmac();

    
        public byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int dkLen)
        {
            if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
            if (dkLen < 1) throw new ArgumentOutOfRangeException(nameof(dkLen));

            int blockCount = (dkLen + HLen - 1) / HLen; 
            var result = new byte[dkLen];

            for (int blockIndex = 1; blockIndex <= blockCount; blockIndex++)
            {
                byte[] block = ComputeBlock(password, salt, iterations, blockIndex);

                int offset = (blockIndex - 1) * HLen;
                int toCopy = Math.Min(HLen, dkLen - offset); 
                Array.Copy(block, 0, result, offset, toCopy);
            }

            return result;
        }

        private byte[] ComputeBlock(byte[] password, byte[] salt, int iterations, int blockIndex)
        {
         
            byte[] u = U_i(password, salt, INT(blockIndex));
            byte[] t = (byte[])u.Clone();

        
            for (int j = 2; j <= iterations; j++)
            {
                u = _sha256Hmac.HashData(u, password);
                t = XorBytes(t, u);
            }

            return t;
        }

        private byte[] CreateBlockMessage(byte[] salt, int index)
        {
            return Concat(salt, INT(index));
        }

        private byte[] XorBytes(byte[] a, byte[] b)
        {
            var result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }

        private byte[] U_i(byte[] key, byte[] salt, byte[] INT)
        {
            return _sha256Hmac.HashData(Concat(salt, INT), key);
        }

        private byte[] Concat(byte[] salt, byte[] INT)
        {
            var result = new byte[salt.Length + INT.Length];

            for (int i = 0; i < salt.Length; i++)
            {
                result[i] = salt[i];
            }

            var INTOffset = salt.Length;

            for (int i = 0; i < INT.Length; i++)
            {
                result[INTOffset + i] = INT[i];
            }
            return result;
        }

        private byte[] INT(int index)
        {
            return UintToBigEndian(index);
        }

        private byte[] UintToBigEndian(int a)
        {
            var bytes = new byte[4];

            bytes[0] = (byte)((a >> 24) & 0xFF);
            bytes[1] = (byte)((a >> 16) & 0xFF);
            bytes[2] = (byte)((a >> 8) & 0xFF);
            bytes[3] = (byte)(a & 0xFF);

            return bytes;
        }
    }
}