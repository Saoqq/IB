using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace root
{
    public static class Program
    {
        enum EncryptionMode
        {
            ECB,
            CBC,
            OFB
        }

        private const int N = 7;

        private const ulong Key = 0x96EA704CFB1CF672;

        private static BitArray IV;

        private const int BlockBranchSize = sizeof(uint);
        private const int BlockSize = BlockBranchSize * 4;

        static ushort vpravo16(ushort x, int t) => (ushort) ((x >> t) | (x << (16 - t)));

        static uint vpravo32(uint x, int t) => (x >> t) | (x << (32 - t));

        static ulong vpravo64(ulong x, int t) => (x >> t) | (x << (64 - t));

        static uint vlevo16(ushort x, int t) => (ushort) ((x << t) | (x >> (16 - t)));

        static uint vlevo32(uint x, int t) => (x << t) | (x >> (32 - t));

        static ulong vlevo64(ulong x, int t) => (x << t) | (x >> (64 - t));

        private static uint Ki(int i) => (uint) vpravo64(Key, i * 8);

        private static uint F(uint x1, uint x2, uint x3, uint kI) => (vlevo32(x1, 4) & vpravo32(x2, 3) | x3 >> 2) ^ kI;

        private static byte[] EncodeBlock(byte[] block)
        {
            var x1 = BitConverter.ToUInt32(block, 0);
            var x2 = BitConverter.ToUInt32(block, BlockBranchSize);
            var x3 = BitConverter.ToUInt32(block, BlockBranchSize * 2);
            var x4 = BitConverter.ToUInt32(block, BlockBranchSize * 3);

            for (var i = 0; i < N; i++)
            {
                var keyI = Ki(i);
                var x4I = x4 ^ F(x1, x2, x3, keyI);

                if (i < N - 1)
                {
                    x4 = x1;
                    x1 = x2;
                    x2 = x3;
                    x3 = x4I;
                }
                else
                {
                    x4 = x4I;
                }
            }

            return new[]
            {
                BitConverter.GetBytes(x1),
                BitConverter.GetBytes(x2),
                BitConverter.GetBytes(x3),
                BitConverter.GetBytes(x4)
            }.SelectMany(x => x).ToArray();
        }

        private static byte[] DecodeBlock(byte[] block)
        {
            var x1 = BitConverter.ToUInt32(block, 0);
            var x2 = BitConverter.ToUInt32(block, BlockBranchSize);
            var x3 = BitConverter.ToUInt32(block, BlockBranchSize * 2);
            var x4 = BitConverter.ToUInt32(block, BlockBranchSize * 3);

            for (var i = N - 1; i >= 0; i--)
            {
                var keyI = Ki(i);
                var x4I = x4 ^ F(x1, x2, x3, keyI);

                if (i > 0)
                {
                    x4 = x3;
                    x3 = x2;
                    x2 = x1;
                    x1 = x4I;
                }
                else
                {
                    x4 = x4I;
                }
            }

            return new[]
            {
                BitConverter.GetBytes(x1),
                BitConverter.GetBytes(x2),
                BitConverter.GetBytes(x3),
                BitConverter.GetBytes(x4)
            }.SelectMany(x => x).ToArray();
        }

        private static void Encode(ref byte[] data, EncryptionMode mode)
        {
            var encrypted = new byte[data.Length];
            var block = new byte[BlockSize];

            switch (mode)
            {
                case EncryptionMode.ECB:
                    for (var i = 0; i < data.Length - 1; i += BlockSize)
                    {
                        Array.Copy(data, i, block, 0, BlockSize);
                        Array.Copy(EncodeBlock(block), 0, encrypted, i, BlockSize);
                    }

                    break;
                case EncryptionMode.CBC:
                    Array.Copy(data, 0, block, 0, BlockSize);
                    new BitArray(block).Xor(IV).CopyTo(block, 0);
                    Array.Copy(EncodeBlock(block), 0, encrypted, 0, BlockSize);

                    for (var i = BlockSize; i < data.Length - 1; i += BlockSize)
                    {
                        var previous = new BitArray(encrypted.Skip(i - BlockSize).Take(BlockSize).ToArray());
                        Array.Copy(data, i, block, 0, BlockSize);
                        previous.Xor(new BitArray(block)).CopyTo(block, 0);
                        Array.Copy(EncodeBlock(block), 0, encrypted, i, BlockSize);
                    }

                    break;
                case EncryptionMode.OFB:
                    IV.CopyTo(block, 0);
                    for (var i = 0; i < data.Length - 1; i += BlockSize)
                    {
                        block = EncodeBlock(block);

                        new BitArray(data.Skip(i).Take(BlockSize).ToArray())
                            .Xor(new BitArray(block)).CopyTo(encrypted, i);
                    }

                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
            }

            data = encrypted;
        }

        private static void Decode(ref byte[] data, EncryptionMode mode)
        {
            var decrypted = new byte[data.Length];
            var block = new byte[BlockSize];


            switch (mode)
            {
                case EncryptionMode.ECB:
                    for (var i = 0; i < data.Length - 1; i += BlockSize)
                    {
                        Array.Copy(data, i, block, 0, BlockSize);
                        Array.Copy(DecodeBlock(block), 0, data, i, BlockSize);
                    }

                    break;
                case EncryptionMode.CBC:
                    Array.Copy(data, 0, block, 0, BlockSize);
                    new BitArray(DecodeBlock(block)).Xor(IV).CopyTo(block, 0);
                    Array.Copy(block, 0, decrypted, 0, BlockSize);

                    for (var i = BlockSize; i < data.Length - 1; i += BlockSize)
                    {
                        var previous = new BitArray(data.Skip(i - BlockSize).Take(BlockSize).ToArray());
                        Array.Copy(data, i, block, 0, BlockSize);
                        previous.Xor(new BitArray(DecodeBlock(block))).CopyTo(block, 0);
                        Array.Copy(block, 0, decrypted, i, BlockSize);
                    }

                    break;
                case EncryptionMode.OFB:
                    IV.CopyTo(block, 0);
                    for (var i = 0; i < data.Length - 1; i += BlockSize)
                    {
                        block = EncodeBlock(block);

                        new BitArray(data.Skip(i).Take(BlockSize).ToArray())
                            .Xor(new BitArray(block)).CopyTo(decrypted, i);
                    }

                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
            }

            data = decrypted;
        }

        public static void Main()
        {
            var ivInit = new byte[BlockSize];
            new RNGCryptoServiceProvider().GetBytes(ivInit);
            IV = new BitArray(ivInit);

            var bytes = File.ReadAllBytes(@"C:\Users\Saoq\RiderProjects\IB\root\source.txt");
            var trailingBytesCount = BlockSize - bytes.Length % BlockSize;
            Array.Resize(ref bytes, bytes.Length + trailingBytesCount);

            Encode(ref bytes, EncryptionMode.OFB);
            File.WriteAllBytes(@"C:\Users\Saoq\RiderProjects\IB\root\encoded.txt", bytes);


            Console.WriteLine(Encoding.UTF8.GetString(bytes));
            Decode(ref bytes, EncryptionMode.OFB);

            File.WriteAllBytes(@"C:\Users\Saoq\RiderProjects\IB\root\decoded.txt", bytes);
            Array.Resize(ref bytes, bytes.Length - trailingBytesCount);
            Console.WriteLine(Encoding.UTF8.GetString(bytes));
        }
    }
}