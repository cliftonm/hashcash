using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace NHashcash
{
    public class Minter
    {
        public enum StampFormat
        {
            Version0,
            Version1,
        }

        private byte[] m_CharacterSet = Encoding.ASCII.GetBytes(
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/="
            );

        private Random m_NumberGenerator = new Random();

        /// <summary>
        ///	Makes sure that the stamp format is either 0 or 1, just in case we
        /// start to support say validating another stamp format but not
        /// producing it in the same ship.
        /// </summary>
        /// <param name="format">A StampFormat instance.</param>
        private void ValidateStampFormat(StampFormat format)
        {
            if ((format != StampFormat.Version0) && (format != StampFormat.Version1))
            {
                throw new NotSupportedException(
                    "Only version 0 and version 1 stamps are supported."
                    );
            }
        }

        /// <summary>
        /// Selects a character randomly from the character set defined in m_CharacterSet.
        /// </summary>
        /// <returns>A byte representing the character.</returns>
        private byte GetRandomCharacter()
        {
            byte randomCharacter = this.m_CharacterSet[this.m_NumberGenerator.Next(0, this.m_CharacterSet.Length)];
            return randomCharacter;
        }

        /// <summary>
        /// Counts the number of continious zeros starting from the left hand side
        /// of the stamp to determine the denomination.
        /// </summary>
        /// <param name="stampHash">A byte array representing the SHA1 hash of the stamp.</param>
        /// <returns>The denomination of the stamp.</returns>
        private int GetStampHashDenomination(byte[] stampHash)
        {
            BitArray continiousBits = new BitArray(stampHash);

            int denomination = 0;
            for (int bitIndex = 0; bitIndex < continiousBits.Length; bitIndex++)
            {
                bool bit = continiousBits[bitIndex];

                if (bit != false)
                {
                    break;
                }

                denomination++;
            }

            return denomination;
        }

        /// <summary>
        /// Produces a byte array containing characters from the character set using
        /// the character map provided for selection.
        /// </summary>
        /// <param name="characterMap">
        /// An integer array indicating the indexes of chracters to select from the
        /// character set.
        /// </param>
        /// <param name="totalCharactersInMap">
        /// A count of the actual characters in the map.
        /// </param>
        /// <returns>
        /// A byte array of characters selected from the character set.
        /// </returns>
        private byte[] TranslateCharacterMapToBytes(int[] characterMap, int totalCharactersInMap)
        {
            byte[] hashCounterCharacters = new byte[totalCharactersInMap];
            for (int characterMapIndex = 0; characterMapIndex < totalCharactersInMap; characterMapIndex++)
            {
                int characterIndex = characterMap[characterMapIndex];
                hashCounterCharacters[characterMapIndex] = this.m_CharacterSet[characterIndex];
            }

            return hashCounterCharacters;
        }

        /// <summary>
        /// Takes an integer and converts it to its base n representation where n is defined
        /// by the size of the character set.
        /// </summary>
        /// <param name="hashCounter">The integer to convert.</param>
        /// <returns>A byte array of characters representing the hash counter in base n.</returns>
        private byte[] CreateCounterBasedOnCharacterSet(int hashCounter)
        {
            int quotient = hashCounter;
            int position = 0;

            int[] characterMap = new int[16];

            while (quotient != 0)
            {
                int remainder = quotient % this.m_CharacterSet.Length;
                characterMap[position] = (byte)remainder;

                quotient = quotient / this.m_CharacterSet.Length;

                position++;
            }

            int totalCharactersInMap = position;
            byte[] hashCounterCharacters = this.TranslateCharacterMapToBytes(characterMap, totalCharactersInMap);

            return hashCounterCharacters;
        }

        /// <summary>
        /// This is the main part of the algorithm. It takes a blank template stamp and randomly replaces the
        /// characters after the prefix until 
        /// </summary>
        /// <param name="blankStamp"></param>
        /// <param name="requiredDenomination"></param>
        /// <param name="format"></param>
        /// <param name="prefixLength"></param>
        /// <returns></returns>
        private byte[] ComputePartialCollisionStamp(byte[] blankStamp, int requiredDenomination, StampFormat format, int prefixLength)
        {
            byte[] collisionStamp = blankStamp;

            int randomRangeLowerLimit = prefixLength;
            int randomRangeUpperLimit = collisionStamp.Length;

            SHA1Managed provider = new SHA1Managed();

            int hashCounter = 0;

            bool collisionFound = false;
            while (collisionFound == false)
            {
                if (format == StampFormat.Version1)
                {
                    byte[] hashCounterBytes = this.CreateCounterBasedOnCharacterSet(hashCounter);
                    Array.Copy(
                        hashCounterBytes,
                        0,
                        collisionStamp,
                        collisionStamp.Length - hashCounterBytes.Length,
                        hashCounterBytes.Length
                        );
                    randomRangeUpperLimit = collisionStamp.Length - hashCounterBytes.Length - 1;
                    collisionStamp[randomRangeUpperLimit] = 58;
                }

                int bytePosition = this.m_NumberGenerator.Next(randomRangeLowerLimit, randomRangeUpperLimit);
                byte characterByte = this.GetRandomCharacter();
                collisionStamp[bytePosition] = characterByte;

                byte[] collisionStampHash = provider.ComputeHash(collisionStamp);
                collisionFound = this.IsCollisionOfRequiredDenomination(collisionStampHash, requiredDenomination);

                hashCounter++;
            }

            return collisionStamp;
        }

        /// <summary>
        /// Checks that the SHA1 hash collides with leading zeros up to the required denomination.
        /// </summary>
        /// <param name="collisionStampHash">SHA1 hash of the stamp.</param>
        /// <param name="requiredDenomination">The required denomination to get a true back.</param>
        /// <returns>True if the hash has enough leading zeros, otherwise false.</returns>
        private bool IsCollisionOfRequiredDenomination(byte[] collisionStampHash, int requiredDenomination)
        {
            bool collisionFound = false;

            int stampDenomination = this.GetStampHashDenomination(collisionStampHash);
            if (stampDenomination >= requiredDenomination)
            {
                collisionFound = true;
            }

            return collisionFound;
        }

        /// <summary>
        /// Finds out what the length of the stamp should be given the prefix and the suggested
        /// 64-byte boundary for SHA1.
        /// </summary>
        /// <param name="prefixLength">The length of the stamp without any padding.</param>
        /// <returns>An integer telling the caller how long the stamp should be all told.</returns>
        private int CalculatePaddedLength(int prefixLength)
        {
            int paddedLength = 0;

            int minimumUnpaddedLength = prefixLength + this.MinimumRandom;
            int sixtyFourByteBoundaryRemainder = minimumUnpaddedLength % 64;

            if (sixtyFourByteBoundaryRemainder != 0)
            {
                paddedLength = minimumUnpaddedLength + (64 - sixtyFourByteBoundaryRemainder);
            }
            else
            {
                paddedLength = minimumUnpaddedLength;
            }

            return paddedLength;
        }

        /// <summary>
        /// Creates a byte array containing the stamp prefix and is padded out to the required length.
        /// </summary>
        /// <param name="resource">The resource that the stamp is being produced for.</param>
        /// <param name="requiredDenomination">The required denomination of the stamp.</param>
        /// <param name="date">The date that the stamp is to be minted for.</param>
        /// <param name="format">The format of the stamp.</param>
        /// <param name="prefixLength">The length of the stamp prefix after all its elements have been pieced together.</param>
        /// <returns>A byte array containing the stamp prefix and the required amount of padding.</returns>
        private byte[] CreateBlankStamp(string resource, int requiredDenomination, DateTime date, StampFormat format, out int prefixLength)
        {
            byte[] stampPrefixBytes = this.GenerateStampPrefixBytes(resource, requiredDenomination, date, format);
            prefixLength = stampPrefixBytes.Length;

            int paddedLength = this.CalculatePaddedLength(prefixLength);

            byte[] blankStamp = new byte[paddedLength];
            Array.Copy(stampPrefixBytes, blankStamp, stampPrefixBytes.Length);

            return blankStamp;
        }

        /// <summary>
        /// Generates the stamp prefix bytes from the inputs.
        /// </summary>
        /// <param name="resource">The resource that the stamp is being produced for.</param>
        /// <param name="requiredDenomination">The required denomination of the stamp.</param>
        /// <param name="date">The date that the stamp is to be minted for.</param>
        /// <param name="format">The format of the stamp to be produced.</param>
        /// <returns>A byte array containing the stamp prefix.</returns>
        private byte[] GenerateStampPrefixBytes(string resource, int requiredDenomination, DateTime date, StampFormat format)
        {
            string stampPrefix = null;
            string stampDate = date.ToString("yyMMdd");         // BUG!  Was yymmdd

            switch (format)
            {
                case StampFormat.Version0:
                    stampPrefix = string.Format(
                        "0:{0}:{1}:",
                        stampDate,
                        resource
                        );
                    break;

                case StampFormat.Version1:
                    stampPrefix = string.Format(
                        "1:{0}:{1}:{2}::",
                        requiredDenomination,
                        stampDate,
                        resource
                        );
                    break;
            }

            byte[] stampPrefixBytes = Encoding.ASCII.GetBytes(stampPrefix);

            return stampPrefixBytes;
        }

        /// <summary>
        /// Validates that the denomination is greater than one and between the minimum and maximum denominations.
        /// </summary>
        /// <param name="requiredDenomination">The required denomination.</param>
        private void ValidateRequiredDenomination(int requiredDenomination)
        {
            if ((requiredDenomination <= 0) || (requiredDenomination > this.MaximumDenomination) || (requiredDenomination < this.MinimumDenomination))
            {
                string message = string.Format(
                    "The required denomination must be between {0} and {1} inclusive.",
                    this.MinimumDenomination,
                    this.MaximumDenomination
                    );
                throw new ArgumentOutOfRangeException("requiredDenomination", requiredDenomination, message);
            }
        }

        /// <summary>
        /// Validates that the resource is not null or a zero-length/empty string.
        /// </summary>
        /// <param name="resource"></param>
        private void ValidateResource(string resource)
        {
            if ((resource == null) || (resource == string.Empty))
            {
                throw new ArgumentException("The resource cannot be null or zero length.", "resource");
            }
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource)
        {
            return this.Mint(resource, this.DefaultDenomination, DateTime.Now, this.DefaultFormat);
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <param name="requiredDenomination">The required denomination of the stamp.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource, int requiredDenomination)
        {
            return this.Mint(resource, requiredDenomination, DateTime.Now, this.DefaultFormat);
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <param name="date">The date that the stamp is to be minted for.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource, DateTime date)
        {
            return this.Mint(resource, this.DefaultDenomination, date, this.DefaultFormat);
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <param name="format">The format of the stamp to be produced.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource, StampFormat format)
        {
            return this.Mint(resource, this.DefaultDenomination, DateTime.Now, format);
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <param name="date">The date that the stamp is to be minted for.</param>
        /// <param name="format">The format of the stamp to be produced.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource, DateTime date, StampFormat format)
        {
            return this.Mint(resource, this.DefaultDenomination, date, format);
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <param name="requiredDenomination">The required denomination of the stamp.</param>
        /// <param name="date">The date that the stamp is to be minted for.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource, int requiredDenomination, DateTime date)
        {
            return this.Mint(resource, requiredDenomination, date, this.DefaultFormat);
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <param name="requiredDenomination">The required denomination of the stamp.</param>
        /// <param name="format">The format of the stamp to be produced.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource, int requiredDenomination, StampFormat format)
        {
            return this.Mint(resource, requiredDenomination, DateTime.Now, format);
        }

        /// <summary>
        /// Mints a stamp given the input parameters.
        /// </summary>
        /// <param name="resource">The resource that the stamp is to be minted for.</param>
        /// <param name="requiredDenomination">The required denomination of the stamp.</param>
        /// <param name="date">The date that the stamp is to be minted for.</param>
        /// <param name="format">The format of the stamp to be produced.</param>
        /// <returns>A string representation of the hashcash stamp.</returns>
        public string Mint(string resource, int requiredDenomination, DateTime date, StampFormat format)
        {
            this.ValidateResource(resource);
            this.ValidateRequiredDenomination(requiredDenomination);
            this.ValidateStampFormat(format);

            int prefixLength;
            byte[] blankStamp = this.CreateBlankStamp(resource, requiredDenomination, date, format, out prefixLength);
            byte[] collisionStamp = this.ComputePartialCollisionStamp(blankStamp, requiredDenomination, format, prefixLength);

            string stamp = Encoding.ASCII.GetString(collisionStamp);

            return stamp;
        }

        private int m_DefaultDenomination = 20;

        public int DefaultDenomination
        {
            get { return this.m_DefaultDenomination; }
            set { this.m_DefaultDenomination = value; }
        }

        private StampFormat m_DefaultFormat;

        public StampFormat DefaultFormat
        {
            get { return this.m_DefaultFormat; }
            set { this.m_DefaultFormat = value; }
        }

        private int m_MaximumDenomination = 32;

        public int MaximumDenomination
        {
            get { return this.m_MaximumDenomination; }
            set { this.m_MaximumDenomination = value; }
        }

        private int m_MinimumDenomination = 16;

        public int MinimumDenomination
        {
            get { return this.m_MinimumDenomination; }
            set { this.m_MinimumDenomination = value; }
        }

        private int m_MinimumRandom = 16;

        public int MinimumRandom
        {
            get { return this.m_MinimumRandom; }
            set { this.m_MinimumRandom = value; }
        }
    }
}
