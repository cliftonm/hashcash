using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Demo
{
    public class HashCashException : ApplicationException
    {
        public HashCashException(string msg) : base(msg)
        {
        }
    }

    public class HashCash
    {
        public int Iterations { get; protected set; }

        private Random rnd = new Random();
        private int counter;
        private string rand;
        private int zbits;
        private DateTime msgDate;
        private string resource;
        private int bytesToCheck;
        private int remainderBitsToCheck;
        private byte remainderMask;

        private readonly int counterMax = (int)Math.Pow(2, 21);
        private SHA1 sha;
        private byte[] zArray;

        private const int COUNTER_IDX = 6;   // index into header for the counter.

        public HashCash(string resource, int zbits = 20)
        {
            rand = GetRandomAlphaNumeric();
            this.msgDate = DateTime.Now;
            this.resource = resource;
            this.zbits = zbits;
            Initialize();
        }

        public HashCash(DateTime msgDate, string resource, int zbits = 20)
        {
            rand = GetRandomAlphaNumeric();
            this.msgDate = msgDate;
            this.resource = resource;
            this.zbits = zbits;
            Initialize();
        }

        public HashCash(DateTime msgDate, string resource, string rand, int zbits = 20)
        {
            this.rand = rand;
            this.msgDate = msgDate;
            this.resource = resource;
            this.zbits = zbits;
            Initialize();
        }

        public static bool Verify(string header)
        {
            // We assume the bits that are going to be 0 are going to be between 10 and 99.
            int zbits = int.Parse(header.Substring(2, 2));
            int bytesToCheck = zbits / 8;
            int remainderBitsToCheck = zbits % 8;
            byte[] zArray = Enumerable.Repeat((byte)0x00, bytesToCheck).ToArray();
            byte remainderMask = (byte)(0xFF << (8 - remainderBitsToCheck));
            SHA1CryptoServiceProvider sha = new SHA1CryptoServiceProvider();
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(header));

            return hash.Take(bytesToCheck).SequenceEqual(zArray) && ((hash[bytesToCheck] & remainderMask) == 0);
        }

        public string Compute()
        {
            string[] headerParts = new string[]
                {
                    "1",
                    zbits.ToString(),
                    msgDate.ToString("yyMMddhhmmss"),
                    resource,
                    "",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(rand)),
                    Convert.ToBase64String(BitConverter.GetBytes(counter)) // .Reverse().SkipWhile(b=>b==0).ToArray()),
                };

            string ret = String.Join(":", headerParts);
            counter = int.MinValue;
            Iterations = 0;

            while (!AcceptableHeader(ret))
            {
                headerParts[COUNTER_IDX] = Convert.ToBase64String(BitConverter.GetBytes(counter));
                ret = String.Join(":", headerParts);

                // Failed 
                if (counter == int.MaxValue)
                {
                    throw new HashCashException("Failed to find solution.");
                }

                ++counter;
                ++Iterations;
            }

            return ret;
        }

        public string GetRandomAlphaNumeric(int len = 8)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            return new String(chars.Select(c => chars[rnd.Next(chars.Length)]).Take(len).ToArray());
        }

        private void Initialize()
        {
            counter = 0;
            sha = new SHA1CryptoServiceProvider();
            bytesToCheck = zbits / 8;
            remainderBitsToCheck = zbits % 8;
            zArray = Enumerable.Repeat((byte)0x00, bytesToCheck).ToArray();
            remainderMask = (byte)(0xFF << (8 - remainderBitsToCheck));
        }

        private bool AcceptableHeader(string header)
        {
            // Testing true case:
            // byte[] hash = new byte[] { 0, 0, 0, 0, 0, 0, 0 };

            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(header));

            // Alternative: return StructuralComparisons.StructuralEqualityComparer.Equals(a1, a2);
            return hash.Take(bytesToCheck).SequenceEqual(zArray) && ((hash[bytesToCheck] & remainderMask) == 0);
        }
    }
}
