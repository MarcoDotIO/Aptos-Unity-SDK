using System;
using System.Collections.Generic;
using System.Linq;
using Aptos.BCS;

namespace Aptos.Accounts
{
    /// <summary>
    /// The ED25519 Multi-Public Key implementation.
    /// </summary>
    public class MultiPublicKey : ISerializable
    {
        /// <summary>
        /// The Public Keys themselves.
        /// </summary>
        public List<PublicKey> Keys;

        /// <summary>
        /// The current amount of keys in the keys array.
        /// </summary>
        public byte Threshold;

        /// <summary>
        /// The minimum amount of keys to initialize this class.
        /// </summary>
        public static int MIN_KEYS = 2;

        /// <summary>
        /// The maximum amount of keys allowed for initialization.
        /// </summary>
        public static int MAX_KEYS = 32;

        /// <summary>
        /// The minimum threshold amount.
        /// </summary>
        public static int MIN_THRESHOLD = 1;

        /// <summary>
        /// Initializer for the MultiPublicKey.
        /// </summary>
        /// <param name="Keys">The Public Keys themselves.</param>
        /// <param name="Threshold">The current amount of keys in the keys array.</param>
        /// <param name="Checked">Verify whether the amount of keys fit within the threshold from 2 to 32 keys, both sides are inclusive.</param>
        /// <exception cref="Exception"></exception>
        public MultiPublicKey(List<PublicKey> Keys, byte Threshold, bool Checked = true)
        {
            if(Checked)
            {
                if(!(MIN_KEYS <= Keys.Count && Keys.Count <= MAX_KEYS))
                    throw new ArgumentException("Must have between " + MIN_KEYS + " and " + MAX_KEYS + " keys.");

                if(!(MIN_THRESHOLD <= Threshold && Threshold < Keys.Count))
                    throw new ArgumentException("Threshold must be between " +MIN_THRESHOLD + " and " + Keys.Count);
            }

            this.Keys = Keys;
            this.Threshold = Threshold;
        }

        public override string ToString()
        {
            return string.Format("{0}-of-{1} Multi-Ed25519 public key", this.Threshold, this.Keys.Count);
        }

        public bool Verify(byte[] data, MultiSignature signature)
        {
            // Step 1: Ensure that the bitmap matches the expected number of signers based on the threshold
            int signerCount = this.Keys.Count;
            UInt32 bitmap = BitConverter.ToUInt32(signature.GetBitmap().Reverse().ToArray(), 0);

            int validSignaturesCount = 0;

            for (int index = 0; index < signerCount; index++)
            {
                // If the bit at the index's position is set, it indicates the presence of a signature
                if ((bitmap & (1u << (31 - index))) != 0)
                {
                    // Try to verify the signature at this index
                    var publicKey = this.Keys[index];
                    var individualSignature = signature.GetSignatures()[validSignaturesCount];

                    if (publicKey.Verify(data, individualSignature))
                    {
                        validSignaturesCount++;
                    }
                    else
                    {
                        // If any signature fails to verify, the entire verification fails
                        return false;
                    }
                }
            }

            // Check if the number of valid signatures meets or exceeds the threshold
            if (validSignaturesCount >= this.Threshold)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Serialize the threshold and concatenated keys of a given threshold signature scheme instance to a Data object.
        ///
        /// This function concatenates the keys of the instance and serializes the threshold and concatenated keys to a Data object.
        /// </summary>
        /// <returns>A bytes array containing the serialized threshold and concatenated keys.</returns>
        public byte[] ToBytes()
        {
            List<byte> concatenatedKeys = new List<byte>();
            foreach (ED25519PublicKey key in this.Keys)
                foreach (byte aByte in key.KeyBytes)
                    concatenatedKeys.Add(aByte);

            concatenatedKeys.Add(this.Threshold);
            return concatenatedKeys.ToArray();
        }

        /// <summary>
        /// Deserialize a Data object to a MultiPublicKey instance.
        ///
        /// This function deserializes the given Data object to a MultiPublicKey instance by extracting the threshold and keys from it.
        /// </summary>
        /// <param name="Key">A Data object containing the serialized threshold and keys of a MultiPublicKey instance.</param>
        /// <returns>A MultiPublicKey instance initialized with the deserialized keys and threshold.</returns>
        /// <exception cref="Exception"></exception>
        public static MultiPublicKey FromBytes(byte[] Key)
        {
            // Get key count and threshold limits.
            int minKeys = MIN_KEYS;
            int maxKeys = MAX_KEYS;
            int minThreshold = MIN_THRESHOLD;

            // Get number of signers.
            int nSigners = Key.Length / ED25519PublicKey.KeyLength;
            if(!(minKeys <= nSigners && nSigners <= maxKeys))
                throw new ArgumentException(string.Format("Must have between {0} and {1} keys.", minKeys, maxKeys));

            // Get threshold.
            byte threshold = Key[Key.Length - 1];
            if(!(minThreshold <= threshold && threshold <= nSigners))
                throw new Exception(string.Format("Threshold must be between {0} and {1}.", minThreshold, nSigners));

            List<PublicKey> keys = new List<PublicKey>(); // Initialize empty keys list.

            for(int i = 0; i < nSigners; i++) // Loop over all signers.
            {
                // Extract public key for signle signer.
                int startByte = i * ED25519PublicKey.KeyLength;
                int endByte = (i + 1) * ED25519PublicKey.KeyLength;

                byte[] tempKey = Key[startByte.. endByte];
                PublicKey publicKey = new ED25519PublicKey(tempKey);
                keys.Add(publicKey);
            }
            return new MultiPublicKey(keys, threshold);
        }

        public void Serialize(Serialization serializer)
        {
            serializer.SerializeBytes(this.ToBytes());
        }
    }
}