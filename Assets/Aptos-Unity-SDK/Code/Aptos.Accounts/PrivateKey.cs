using Aptos.HdWallet.Utils;
using Aptos.BCS;
using Chaos.NaCl;
using System;
using NBitcoin;

namespace Aptos.Accounts
{
    public abstract class PrivateKey: ISerializable
    {
        private byte[] _key;

        public abstract Signature Sign(byte[] message);

        public abstract PublicKey PublicKey();

        public abstract void Serialize(Serialization serializer);
    }

    public abstract class PublicKey: ISerializable
    {
        private byte[] _key;

        public abstract bool Verify(byte[] message, Signature signature);

        public abstract void Serialize(Serialization serializer);
    }

    /// <summary>
    /// Represents a 64-byte extended private key.
    /// An extended private key is a requirement from Choas.NaCl.
    /// 
    /// Note that the hexadecimal string representation is of the 32-byte private key on it's own.
    /// </summary>
    public class ED25519PrivateKey: PrivateKey
    {
        /// <summary>
        /// Extended private key length.
        /// </summary>
        public const int ExtendedKeyLength = 64;

        /// <summary>
        /// Private key length.
        /// </summary>
        public const int KeyLength = 32;

        /// <summary>
        /// Hex string representation of private key.
        /// </summary>
        private byte[] _key;

        /// <summary>
        /// The 64-byte extended private key.
        /// This key is used internally for signing.
        /// A public accessor that returns a 32-byte private is found in <see cref="_keyBytes">KeyBytes</see>
        /// </summary>
        private byte[] _extendedKeyBytes;

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
        /// The 32-byte private key in bytes.
        /// Checks if we have the 32-byte private key or 64-byte extended key, 
        /// otherwise uses the string representation to create both.
        /// </summary>
        public byte[] KeyBytes
        {
            get
            {
                // if the private key bytes have not being initialized, but a 32-byte (64 character) string private has been set
                if (_extendedKeyBytes == null && _key != null)
                {
                    _extendedKeyBytes = Ed25519.ExpandedPrivateKeyFromSeed(_key);
                }
                return _key;
            }

            set
            {
                if(value.Length != KeyLength)
                    throw new ArgumentException("Invalid key length: ", nameof(value));

                _key = value;
                _extendedKeyBytes = Ed25519.ExpandedPrivateKeyFromSeed(value);
            }
        }

        /// <summary>
        /// Initializes the PrivateKey object with a 64 byte array that represents the expanded private key from seed.   
        /// For example, using: <c>Ed25519.ExpandedPrivateKeyFromSeed(seed)</c>.   
        /// This constructor is expected to be called from the <see cref="Account.Account()">Account</see> constructor.   
        /// Note: To create a private key from a 32-byte string see <see cref="PrivateKey(string key)">PrivateKey(string key)</see>
        /// </summary>
        /// <param name="privateKey">64-byte array representation of the private key.</param>
        public ED25519PrivateKey(byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            if (privateKey.Length != KeyLength)
                throw new ArgumentException("Invalid key length: ", nameof(privateKey));
            KeyBytes = new byte[KeyLength];
            Array.Copy(privateKey, KeyBytes, KeyLength);

            _extendedKeyBytes = new byte[Ed25519.ExpandedPrivateKeySizeInBytes];
            Array.Copy(Ed25519.ExpandedPrivateKeyFromSeed(KeyBytes), _extendedKeyBytes, Ed25519.ExpandedPrivateKeySizeInBytes);
        }

        /// <summary>
        /// Initializes the PrivateKey object with a 64 character (32-byte) ASCII representation of a private key.   
        /// Note: The undelying cryptographic library (Chaos.NaCL) uses an extended private key (64 byte) for fast computation.   
        /// This hex string is used as a seed to create an extended private key when <see cref="KeyBytes">KeyBytes</see> is requested.
        /// </summary>
        /// <param name="key">The private key as an ASCII encoded string.   
        /// Example: <c>0x64f57603b58af16907c18a866123286e1cbce89790613558dc1775abb3fc5c8c</c></param>
        public ED25519PrivateKey(string key)
        {
            if(!HdWallet.Utils.Utils.IsValidAddress(key))
                throw new ArgumentException("Invalid key", nameof(key));

            this.Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>
        /// Create a private key from a string literal.
        /// Conforms to the standard Python and Typescript Aptos SDK.
        /// </summary>
        /// <param name="key">The private key as an ASCII encoded string.</param>
        /// <returns>Private key object.</returns>
        public static ED25519PrivateKey FromHex(string key)
        {
            return new ED25519PrivateKey(key);
        }

        /// <summary>
        /// Initialize the PrivateKey object from the given string.
        /// </summary>
        /// <param name="key">The private key as a hex encoded byte array.</param>
        public ED25519PrivateKey(ReadOnlySpan<byte> privateKey)
        {
            if (privateKey.Length != KeyLength)
                throw new ArgumentException("Invalid key length: ", nameof(privateKey));
            KeyBytes = new byte[KeyLength];
            privateKey.CopyTo(KeyBytes.AsSpan());

            _extendedKeyBytes = Ed25519.ExpandedPrivateKeyFromSeed(KeyBytes);
        }

        /// <summary>
        /// Derives public key from the private key bytes.
        /// </summary>
        /// <returns>PublicKey object.</returns>
        public override PublicKey PublicKey()
        {
            ED25519PublicKey publicKey = new ED25519PublicKey(Ed25519.PublicKeyFromSeed(KeyBytes));
            return publicKey;
        }

        public static PrivateKey Random()
        {
            byte[] seed = new byte[Ed25519.PrivateKeySeedSizeInBytes];
            RandomUtils.GetBytes(seed);
            return new ED25519PrivateKey(seed);
        }

        /// <summary>
        /// Compartor for two private keys.
        /// </summary>
        /// <param name="lhs">First private key in comparison..</param>
        /// <param name="rhs">Second private key in comparison.</param>
        /// <returns></returns>
        public static bool operator ==(ED25519PrivateKey lhs, ED25519PrivateKey rhs)
        {

            if (lhs is null)
            {
                if (rhs is null)
                    return true;

                // Only the left side is null.
                return false;
            }
            // Equals handles case of null on right side.
            return lhs.Equals(rhs);
        }

        public static bool operator !=(ED25519PrivateKey lhs, ED25519PrivateKey rhs) => !(lhs == rhs);

        /// <summary>
        /// Sign a message using the extended private key.
        /// </summary>
        /// <param name="message">The message to sign, represented in bytes.</param>
        /// <returns>The signature generated for the message as an object</returns>
        public override Signature Sign(byte[] message)
        {
            ArraySegment<byte> signature = new ArraySegment<byte>(new byte[64]);
            Ed25519.Sign(signature,
                new ArraySegment<byte>(message),
                new ArraySegment<byte>(_extendedKeyBytes));
            return new Signature(signature.Array);
        }

        /// <summary>
        /// Serialize private key
        /// </summary>
        /// <param name="serializer">Serializer object</param>
        public override void Serialize(Serialization serializer)
        {
            serializer.SerializeBytes(this.KeyBytes);
        }

        /// <inheritdoc cref="Equals(object)"/>
        public override bool Equals(object obj)
        {
            if(obj is ED25519PrivateKey privateKey)
                return privateKey.Key == this.Key;

            return false;
        }

        /// <inheritdoc cref="GetHashCode"/>
        public override int GetHashCode() => Key.GetHashCode();

        /// <inheritdoc cref="ToString"/>
        public override string ToString() => Key;

        /// <summary>
        /// Convert a PrivateKey object to hexadecimal string representation of private key.
        /// </summary>
        /// <param name="privateKey">The PrivateKey object.</param>
        /// <returns>Hexadecimal string representing the private key.</returns>
        public static implicit operator string(ED25519PrivateKey privateKey) => privateKey.Key;
    }
}