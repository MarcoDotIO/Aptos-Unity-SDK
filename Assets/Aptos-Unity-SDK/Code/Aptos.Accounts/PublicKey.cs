using Aptos.HdWallet.Utils;
using Aptos.BCS;
using Chaos.NaCl;
using System;

namespace Aptos.Accounts
{
    /// <summary>
    /// Represents a 32-byte public key.
    /// </summary>
    public class ED25519PublicKey: PublicKey
    {
        /// <summary>
        /// Public key length.
        /// </summary>
        public const int KeyLength = 32;

        /// <summary>
        /// Hex string representation of public key.
        /// </summary>
        private byte[] _key;

        /// <summary>
        /// The key as a hexadecimal string
        /// </summary>
        public string Key
        {
            get
            {
                string addressHex = CryptoBytes.ToHexStringLower(_key);
                string returnValue = $"0x{addressHex}";
                return returnValue;
            }

            set => _key = CryptoBytes.FromHexString(value.StartsWith("0x") ? value.Substring(2) : value);
        }

        /// <summary>
        /// The key in bytes.
        /// </summary>
        public byte[] KeyBytes
        {
            get => _key;

            set => _key = value;
        }

        /// <summary>
        /// Initializes the PublicKey object with a given byte array.
        /// </summary>
        /// <param name="publicKey">The public key as byte array.</param>
        public ED25519PublicKey(byte[] publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.Length != KeyLength)
                throw new ArgumentException("Invalid key length: ", nameof(publicKey));
            KeyBytes = new byte[KeyLength];
            Array.Copy(publicKey, KeyBytes, KeyLength);
        }

        /// <summary>
        /// Initializes the PublicKey object with a given hexadecimal representation of public .
        /// </summary>
        /// <param name="key">The public key as a hexadecimal string.   
        /// Example: <c>0x586e3c8d447d7679222e139033e3820235e33da5091e9b0bb8f1a112cf0c8ff5</c>
        /// </param> 
        public ED25519PublicKey(string key)
        {
            if (!Utils.IsValidAddress(key))
                throw new ArgumentException("Invalid key", nameof(key));

            this.Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>
        /// Initialize the PublicKey object from the given string.
        /// </summary>
        /// <param name="publicKey">The public key as a byte array.</param>
        public ED25519PublicKey(ReadOnlySpan<byte> publicKey)
        {
            if (publicKey.Length != KeyLength)
                throw new ArgumentException("Invalid key length: ", nameof(publicKey));
            KeyBytes = new byte[KeyLength];
            publicKey.CopyTo(KeyBytes.AsSpan());
        }

        /// <summary>
        /// Verify a signed message using the current public key.
        /// </summary>
        /// <param name="message">Message that was signed.</param>
        /// <param name="signature">The signature from the message.</param>
        /// <returns></returns>
        public override bool Verify(byte[] message, Signature signature)
        {
            return Ed25519.Verify(signature.Data(), message, KeyBytes);
        }

        /// <summary>
        /// Check if PubliKey is a valid on the Ed25519 curve.
        /// </summary>
        /// <returns>Returns true if public key is on the curve.</returns>
        public bool IsOnCurve() => KeyBytes.IsOnCurve();

        /// <summary>
        /// Serialize public key
        /// </summary>
        /// <param name="serializer">Serializer object</param>
        public override void Serialize(Serialization serializer)
        {
            serializer.SerializeBytes(this.KeyBytes);
        }

        public static ED25519PublicKey Deserialize(Deserialization deserializer)
        {
            byte[] keyBytes = deserializer.ToBytes();
            if (keyBytes.Length != KeyLength)
                throw new Exception("Length mismatch. Expected: " + KeyLength + ", Actual: " + keyBytes.Length);

            return new ED25519PublicKey(keyBytes);
        }

        /// <inheritdoc cref="object.Equals(object)"/>
        public override bool Equals(object obj)
        {
            if (obj is ED25519PublicKey publicKey)
 
                return publicKey.Key.Equals(Key);

            return false;
        }

        /// <summary>
        /// Value used as a hash
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode() => Key.GetHashCode();

        /// <summary>
        /// ToString implementation return the key as a hex string.
        /// </summary>
        /// <returns></returns>
        public override string ToString() => Key;

        /// <summary>
        /// Compares two public key objects.
        /// </summary>
        /// <param name="lhs"></param>
        /// <param name="rhs"></param>
        /// <returns>True if public keys are equal. False is public keys are not equal.</returns>
        public static bool operator ==(ED25519PublicKey lhs, ED25519PublicKey rhs)
        {
            if (lhs is null)
            {
                if (rhs is null)
                    return true;

                return false;
            }
            return lhs.Equals(rhs);
        }

        /// <summary>
        /// Compares two public key objects for inequality.
        /// </summary>
        /// <param name="lhs"></param>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static bool operator !=(ED25519PublicKey lhs, ED25519PublicKey rhs) => lhs == rhs;

        /// <summary>
        /// Convert a PublicKey object to hex encoded string representatio public key.
        /// </summary>
        /// <param name="publicKey">The PublicKey object.</param>
        /// <returns>Hex encoded string representing the public key.</returns>
        public static implicit operator string(ED25519PublicKey publicKey) => publicKey.Key;

        /// <summary>
        /// Convert Hex encoded string of a public key to PublicKey object.
        /// </summary>
        /// <param name="publicKey">hex encoded string representing a public key.</param>
        /// <returns>PublicKey object.</returns>
        public static explicit operator ED25519PublicKey(string publicKey) => new ED25519PublicKey(publicKey);

        /// <summary>
        /// Convert a PublicKey object to a byte array representation of a public key.
        /// </summary>
        /// <param name="publicKey">The PublicKey object.</param>
        /// <returns>Public key as a byte array.</returns>
        public static implicit operator byte[](ED25519PublicKey publicKey) => publicKey._key;

        /// <summary>
        /// Convert byte array representation of a public key to a PublicKey object.
        /// </summary>
        /// <param name="keyBytes">The public key as a byte array.</param>
        /// <returns>PublicKey object.</returns>
        public static explicit operator ED25519PublicKey(byte[] keyBytes) => new ED25519PublicKey(keyBytes);
    }
}