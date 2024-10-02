using System;
using System.Security.Cryptography;

namespace FirmaXadesNet.Signature
{
    // [rg] Codice da:
    // https://github.com/scottbrady91/Blog-Example-Classes/tree/master/XmlSigning
    public class ECDsa256SignatureDescription : SignatureDescription
    {
        public ECDsa256SignatureDescription()
        {
            KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
        }

        public override HashAlgorithm CreateDigest() => SHA256.Create();

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256)
                throw new InvalidOperationException("Requires EC key using P-256");
            return new EcdsaSignatureFormatter(ecdsa);
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256)
                throw new InvalidOperationException("Requires EC key using P-256");
            return new EcdsaSignatureDeformatter(ecdsa);
        }
    }

    public class ECDsa384SignatureDescription : SignatureDescription
    {
        public ECDsa384SignatureDescription()
        {
            KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
        }

        public override HashAlgorithm CreateDigest() => SHA384.Create();

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 384)
                throw new InvalidOperationException("Requires EC key using P-384");
            return new EcdsaSignatureFormatter(ecdsa);
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 384)
                throw new InvalidOperationException("Requires EC key using P-384");
            return new EcdsaSignatureDeformatter(ecdsa);
        }
    }

    public class ECDsa512SignatureDescription : SignatureDescription
    {
        public ECDsa512SignatureDescription()
        {
            KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
        }

        public override HashAlgorithm CreateDigest() => SHA512.Create();

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 512)
                throw new InvalidOperationException("Requires EC key using P-512");
            return new EcdsaSignatureFormatter(ecdsa);
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 512)
                throw new InvalidOperationException("Requires EC key using P-512");
            return new EcdsaSignatureDeformatter(ecdsa);
        }
    }

    public class EcdsaSignatureFormatter : AsymmetricSignatureFormatter
    {
        private ECDsa key;

        public EcdsaSignatureFormatter(ECDsa key) => this.key = key;

        public override void SetKey(AsymmetricAlgorithm key) => this.key = key as ECDsa;

        public override void SetHashAlgorithm(string strName) { }

        public override byte[] CreateSignature(byte[] rgbHash) => key.SignHash(rgbHash);
    }

    public class EcdsaSignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private ECDsa key;

        public EcdsaSignatureDeformatter(ECDsa key) => this.key = key;

        public override void SetKey(AsymmetricAlgorithm key) => this.key = key as ECDsa;

        public override void SetHashAlgorithm(string strName) { }

        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            var isValid = key.VerifyHash(rgbHash, rgbSignature);
            return isValid;
        }
    }
}
