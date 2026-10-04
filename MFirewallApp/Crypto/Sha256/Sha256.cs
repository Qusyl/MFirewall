using System.ComponentModel;
using System.Reflection.Metadata;
using System.Text;
using MFirewallApp.Common;

namespace MFirewallApp.Crypto.Sha256Hmac
{

    public class Sha256
    {
        private sealed class HashState
        {
            public uint H0;
            public uint H1;
            public uint H2;
            public uint H3;
            public uint H4;
            public uint H5;
            public uint H6;
            public uint H7;
        }

        private sealed class WorkingState
        {
            public uint A;
            public uint B;

            public uint C;

            public uint D;

            public uint E;

            public uint F;

            public uint G;

            public uint H;
        }
        
        public byte[] HashData(byte[] data)
        {
            var messageBytes = data;

            var padded = PaddingMessage(messageBytes);

            var blocks = padded.Chunk(64).ToArray();


            uint[] k = FillConstants();

            HashState state = new HashState
            {
                H0 = 0x6a09e667,
                H1 = 0xbb67ae85,
                H2 = 0x3c6ef372,
                H3 = 0xa54ff53a,
                H4 = 0x510e527f,
                H5 = 0x9b05688c,
                H6 = 0x1f83d9ab,
                H7 = 0x5be0cd19
            };

            int len = data.Length;

            int pdLen = padded.Length;

            int bloLen = blocks.Length;

          
            foreach(var block in blocks)
            {
                var words = CreateWords(block);

                var messSch = MessageSchedule(words);
                 
                CompressBlock(messSch, k, state);
            }

            byte[] hashed = new byte[32];

            uint[] reg_states = new uint[]
            {
                state.H0,
                state.H1,
                state.H2,
                state.H3,
                state.H4,
                state.H5,
                state.H6,
                state.H7,
            };
            int j = 0;
            for (int i = 0; i <= hashed.Length - 4; i += 4)
            {
                byte[] bytes = ToBytes(reg_states[j]);
                hashed[i] = bytes[0];
                hashed[i + 1] = bytes[1];
                hashed[i + 2] = bytes[2];
                hashed[i + 3] = bytes[3];
                j++;
            }

            string hex = BitConverter.ToString(hashed).Replace("-", "");
         
            return hashed;
        }
        private uint[] CreateWords(byte[] block)
        {
            var chunks = block.Chunk(4).ToArray();

            var len = chunks.Length;

            var uBlock = new uint[len];
            
            int wIndex = 0;
            foreach (var chunk in chunks)
            {
                uBlock[wIndex] = ToUInt32(chunk[0], chunk[1], chunk[2], chunk[3]);
                wIndex++;
            }

            return uBlock;
        }
        
        private uint[] FillConstants()
        {
            uint[] k = new uint[64];

            var konsts = PrimeGenerator.GeneratePrime();

            for (int i = 0; i < k.Length; i++)
            {
                k[i] = GenerateConstant(konsts[i]);
                
            }
            return k;
        }

        private int FindLength(int messageSize)
        {
            int len = 0;
            do
            {
                len++;
            } while (len < messageSize + 9 || len % 64 != 0);
       
            return len;
        }
        private byte[] PaddingMessage(byte[] message)
        {

            int blockSize = FindLength(message.Length);
            byte[] block = new byte[blockSize];
            int inx_start = 0;

            for (int i = 0; i < message.Length; i++)
            {
                block[i] = message[i];
                inx_start++;
            }

            block[inx_start] = 0x80;

            inx_start++;

            for (int j = inx_start; j < blockSize - 8; j++)
            {
                block[j] = 0x00;

            }
            ulong msgBitLen = (ulong)message.Length * 8;

            for (int k = 7; k >= 0; k--)
            {
                block[blockSize - 8 + k] = (byte)(msgBitLen & 0xFF);
                msgBitLen >>= 8;
            }

       
            return block;
        }

        private uint ToUInt32(byte b0, byte b1, byte b2, byte b3)
        {
            return ((uint)b0 << 24
            | (uint)b1 << 16
            | (uint)b2 << 8
            | (uint)b3 << 0);
        }
        private byte[] ToBytes(uint a)
        {
            byte[] bytes = new byte[4];

            bytes[0] = (byte)(a >> 24);
            bytes[1]= (byte)((a >> 16) & 0xFF);
            bytes[2] = (byte)((a >> 8) & 0xFF);
            bytes[3] = (byte)((a >> 0) & 0xFF);

            return bytes;
         
        }
        

        private uint Rotr(uint value, int shift)
        {
            return ((value >> shift) | (value << (32 - shift)));
        }

        private uint Sigma0(uint value)
        {
            return Rotr(value, 7) ^ Rotr(value, 18) ^ (value >> 3);
        }

        private uint Sigma1(uint value)
        {
            return Rotr(value, 17) ^ Rotr(value, 19) ^ (value >> 10);
        }
        private uint[] MessageSchedule(uint[] w)
        {
            var messedW = new uint[64];

            for (int i = 0; i < w.Length; i++)
            {
                messedW[i] = w[i];
            }

            for (int i = 16; i < 64; i++)
            {
                messedW[i] =
                Sigma1(messedW[i - 2]) +
                messedW[i - 7] +
                Sigma0(messedW[i - 15]) +
                messedW[i - 16];
            }
            return messedW;
        }

        private uint Ch(uint e, uint f, uint g)
        {
            return (e & f) ^ (~e & g);
        }

        private uint Maj(uint a, uint b, uint c)
        {
            return (a & b) ^ (a & c) ^ (b & c);
        }

        private uint SigmaB0(uint a)
        {
            return Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
        }
        private uint SigmaB1(uint e)
        {
            return Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
        }

        private (uint temp1, uint temp2) Round(WorkingState state, uint w, uint k)
        {
            

            var S1 = SigmaB1(state.E);

            var chResult = Ch(state.E, state.F, state.G);

            var temp1 = state.H + S1 + chResult + k + w;

            var s0 = SigmaB0(state.A);

            var majResult = Maj(state.A, state.B, state.C);

            var temp2 = s0 + majResult;

            return (temp1, temp2);
        }
        
        private void RefreshState(WorkingState state, uint temp1, uint temp2)
        {
            var oldA = state.A;
            var oldB = state.B;
            var oldC = state.C;
            var oldD = state.D;
            var oldE = state.E;
            var oldF = state.F;
            var oldG = state.G;
            
            state.A = temp1 + temp2;
            state.B = oldA;
            state.C = oldB;
            state.D = oldC;
            state.E = oldD + temp1;
            state.F = oldE;
            state.G = oldF;
            state.H = oldG;
        }
        private void CompressBlock(uint[] w, uint[] k, HashState state)
        {
            WorkingState workingState = new WorkingState
            {
                A = state.H0,
                B = state.H1,
                C = state.H2,
                D = state.H3,
                E = state.H4,
                F = state.H5,
                G = state.H6,
                H = state.H7

            };

            for (int i = 0; i < 64; i++)
            {
                (uint temp1, uint temp2) round = Round(workingState, w[i], k[i]);

                RefreshState(workingState, round.temp1, round.temp2);
            }

            state.H0 += workingState.A;
            state.H1 += workingState.B;
            state.H2 += workingState.C;
            state.H3 += workingState.D;
            state.H4 += workingState.E;
            state.H5 += workingState.F;
            state.H6 += workingState.G;
            state.H7 += workingState.H;
           
            
        }
        
        private uint GenerateConstant(int prime)
        {
            double cb = Math.Cbrt(prime);

            double fractionalPart = cb - Math.Floor(cb);

            double mod32 =fractionalPart *  Math.Pow(2, 32);

            return (uint)mod32;
        }

    }
}