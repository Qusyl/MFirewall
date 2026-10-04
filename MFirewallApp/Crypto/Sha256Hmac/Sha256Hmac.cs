using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Crypto.Sha256Hmac
{
    public class Sha256Hmac
    {
        private Sha256 _sha256 = new Sha256();

        public byte[] HashData(byte[] message, byte[] key)
        {
            var ks = NormalizeKey(key);

            var k_ipad = CreateIPad(ks);

            var k_opad = CreateOPad(ks);

            var concat = Concat(k_ipad,message);

            var shaConcat = _sha256.HashData(concat);

            var hmac = _sha256.HashData(Concat(k_opad, shaConcat));

            return hmac;
        }
        private byte[] Concat(byte[] k_pad, byte[] message)
        {
            var result = new byte[message.Length + k_pad.Length];

            for (int i = 0; i < k_pad.Length; i++)
            {
                result[i] = k_pad[i];
            }
            var messIndex = result.Length - message.Length;

            for (int i = 0; i < message.Length; i++)
            {
                result[messIndex] = message[i];
                messIndex++;
            }

            return result;
        }
        private byte[] CreateIPad(byte[] k)
        {
            var initByte = new byte[k.Length];

            for (int i = 0; i < k.Length; i++)
            {
                initByte[i] = (byte)(k[i] ^ 0x36);
            }
            return initByte;
        }

        private byte[] CreateOPad(byte[] k)
        {
            var initByte = new byte[k.Length];

            for (int i = 0; i < k.Length; i++)
            {
                initByte[i] = (byte)(k[i] ^ 0x5C);
            }
            return initByte;
        }
        private byte[] NormalizeKey(byte[] key)
        {
            int keyLen = key.Length;

            byte[] normalizedKey = new byte[64];

            if (keyLen == 64)
            {
                for (int i = 0; i < key.Length; i++)
                {
                    normalizedKey[i] = key[i];
                }
                return normalizedKey;
            }

            if (keyLen > 64)
            {
                byte[] sha256Key = _sha256.HashData(key);
                for (int i = 0; i < sha256Key.Length; i++)
                {
                    normalizedKey[i] = sha256Key[i];
                }

                return normalizedKey;
            }

            for (int i = 0; i < keyLen; i++)
            {
                normalizedKey[i] = key[i];

            }
            return normalizedKey;
        }
        

    }
}