using System;
using System.Collections.Generic;
using System.Linq;
using Aptos.BCS;
using Aptos.HdWallet.Utils;

namespace Aptos.Accounts
{
    /// <summary>
    /// The ED25519 Multi-Signature Implementation.
    /// </summary>
    public class MultiSignature : ISerializable
    {
        /// <summary>
        /// The signatures themselves.
        /// </summary>
        List<Signature> Signatures;

        /// <summary>
        /// The compact representation of which keys among a set of N possible keys have signed a given message.
        /// </summary>
        byte[] Bitmap;

        /// <summary>
        /// Initialize the MultiSignature object.
        /// </summary>
        /// <param name="PublicKeyMulti">The multi public key object containing the public keys used to generate the Bitmap.</param>
        /// <param name="SignatureMap">The tuple list containing the public keys associated with their signatures.</param>
        public MultiSignature(
            MultiPublicKey PublicKeyMulti,
            List<Tuple<PublicKey, Signature>> SignatureMap
        )
        {
            this.Signatures = new List<Signature>();
            int bitmap = 0;
            foreach(Tuple<PublicKey, Signature> entry in SignatureMap)
            {
                this.Signatures.Add(entry.Item2);
                int index = PublicKeyMulti.Keys.IndexOf(entry.Item1);
                int shift = 31 - index; // 32 bit positions, left to right.
                bitmap = bitmap | (1 << shift);
            }

            // 4-byte big endian bitmap.
            // self.bitmap = bitmap.to_bytes(4, "big")
            uint uBitmap = ((uint)bitmap).ToBigEndian();
            this.Bitmap = BitConverter.GetBytes(uBitmap);
        }

        public MultiSignature(
            List<Signature> signatures,
            byte[] bitmap
        )
        {
            this.Signatures = signatures;
            this.Bitmap = bitmap;
        }

        /// <summary>
        /// Serialize the concatenated signatures and bitmap of an ED25519 Multi-signature instance to a Data object.
        ///
        /// This function concatenates the signatures of the instance and serializes the concatenated signatures and bitmap to a Data object.
        /// </summary>
        /// <returns>A byte list containing the serialized concatenated signatures and bitmap.</returns>
        public byte[] ToBytes()
        {
            List<byte> concatenatedSignatures = new List<byte>();
            foreach(Signature signature in this.Signatures)
            {
                concatenatedSignatures
                    = concatenatedSignatures.Concat(signature.Data()).ToList();
            }
            concatenatedSignatures
                = concatenatedSignatures.Concat(this.Bitmap).ToList();
            return concatenatedSignatures.ToArray();
        }

        public List<Signature> GetSignatures()
        {
            return this.Signatures;
        }

        public byte[] GetBitmap()
        {
            return this.Bitmap;
        }

        public void Serialize(Serialization serializer)
        {
            serializer.SerializeBytes(this.ToBytes());
        }

        public static MultiSignature Deserialize(Deserialization deserializer)
        {
            byte[] signatureBytes = deserializer.ToBytes();
            int bitmapOffset = signatureBytes.Length - sizeof(UInt32); // Assuming 4 bytes for UInt32
            byte[] bitmapData = new byte[sizeof(UInt32)];
            Array.Copy(signatureBytes, bitmapOffset, bitmapData, 0, sizeof(UInt32));
            UInt32 bitmap = BitConverter.ToUInt32(bitmapData.Reverse().ToArray(), 0); // Adjusting for big-endian as in Swift code

            List<Signature> signatures = new List<Signature>();
            int currentByteIndex = 0;

            for (int position = 0; position < 32; position++)
            {
                if ((bitmap & (1U << (31 - position))) != 0)
                {
                    // Assuming Signature class has a constructor that accepts a byte[] for signature data
                    byte[] signatureData = new byte[Signature.SignatureLength];
                    Array.Copy(signatureBytes, currentByteIndex, signatureData, 0, Signature.SignatureLength);
                    signatures.Add(new Signature(signatureData));
                    currentByteIndex += Signature.SignatureLength;
                }
            }

            return new MultiSignature(signatures, bitmapData); // Assuming a constructor that takes these parameters
        }
    }
}