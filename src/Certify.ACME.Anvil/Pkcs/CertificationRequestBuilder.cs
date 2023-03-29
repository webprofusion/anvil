using System;
using System.Collections.Generic;
using System.Linq;
using Certify.ACME.Anvil.Crypto;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Certify.ACME.Anvil.Pkcs
{
    /// <summary>
    /// Represents a CSR builder.
    /// </summary>
    /// <seealso cref="Certify.ACME.Anvil.Pkcs.ICertificationRequestBuilder" />
    public class CertificationRequestBuilder : ICertificationRequestBuilder
    {
        private static readonly KeyAlgorithmProvider keyAlgorithmProvider = new KeyAlgorithmProvider();
        private string commonName;
        private readonly List<(DerObjectIdentifier Id, string Value)> attributes = new List<(DerObjectIdentifier, string)>();
        private IList<string> subjectAlternativeNames = new List<string>();

        private string pkcsObjectId;
        private AsymmetricCipherKeyPair keyPair;

        /// <summary>
        /// Gets the key.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public IKey Key { get; }

        /// <summary>
        /// Gets the subject alternative names.
        /// </summary>
        /// <value>
        /// The subject alternative names.
        /// </value>
        public IList<string> SubjectAlternativeNames
        {
            get
            {
                return subjectAlternativeNames;
            }
            set
            {
                this.subjectAlternativeNames = value ??
                    throw new ArgumentNullException(nameof(SubjectAlternativeNames));
            }
        }

        private IList<byte[]> tnAuthList = new List<byte[]>();

        /// <summary>
        /// Optional list of Telephone Number Authorization List items to include as extensions. When set CSR will ignore subject names etc.
        /// </summary>
        public IList<byte[]> TnAuthList
        {
            get
            {
                return tnAuthList;
            }
            set
            {
                tnAuthList = value ??
                    throw new ArgumentNullException(nameof(TnAuthList));
            }
        }

        private IList<Uri> crlDistributionPoints = new List<Uri>();

        /// <summary>
        /// Optional list of CRL Distribution point URIs to include
        /// </summary>
        public IList<Uri> CrlDistributionPoints
        {
            get
            {
                return crlDistributionPoints;
            }
            set
            {
                crlDistributionPoints = value ??
                    throw new ArgumentNullException(nameof(CrlDistributionPoints));
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificationRequestBuilder"/> class.
        /// </summary>
        /// <param name="keyInfo">The key information.</param>
        /// <exception cref="System.NotSupportedException">
        /// If the provided key is not one of the supported <seealso cref="KeyAlgorithm"/>.
        /// </exception>
        [Obsolete]
        public CertificationRequestBuilder(KeyInfo keyInfo)
            : this(KeyFactory.FromDer(keyInfo.PrivateKeyInfo))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificationRequestBuilder"/> class.
        /// </summary>
        public CertificationRequestBuilder()
            : this(KeyFactory.NewKey(KeyAlgorithm.RS256))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificationRequestBuilder"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public CertificationRequestBuilder(IKey key)
        {
            Key = key;
        }
        /// <summary>
        /// Adds the distinguished name as certificate subject.
        /// </summary>
        /// <param name="distinguishedName">The distinguished name.</param>
        public void AddName(string distinguishedName)
        {
            X509Name name;
            try
            {
                name = new X509Name(distinguishedName);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentOutOfRangeException(
                    $"{distinguishedName} contains an invalid X509 name.", ex);
            }

            var oidList = name.GetOidList();
            var valueList = name.GetValueList();
            var len = oidList.Count;
            for (var i = 0; i < len; ++i)
            {
                var id = (DerObjectIdentifier)oidList[i];
                var value = valueList[i].ToString();
                attributes.Add((id, value));

                if (id == X509Name.CN)
                {
                    this.commonName = value;
                }
            }
        }

        /// <summary>
        /// Adds the name.
        /// </summary>
        /// <param name="keyOrCommonName">Name of the key or common.</param>
        /// <param name="value">The value.</param>
        /// <exception cref="System.ArgumentOutOfRangeException">
        /// If <paramref name="keyOrCommonName"/> is not a valid X509 name.
        /// </exception>
        public void AddName(string keyOrCommonName, string value)
            => AddName($"{keyOrCommonName}={value}");

        /// <summary>
        /// Generates the CSR.
        /// </summary>
        /// <returns>
        /// The CSR data.
        /// </returns>
        public byte[] Generate(bool requireOcspMustStaple = false)
        {
            return GeneratePkcs10(requireOcspMustStaple);
        }

        /// <summary>
        /// Exports the key used to generate the CSR.
        /// </summary>
        /// <returns>
        /// The key data.
        /// </returns>
        [Obsolete]
        public KeyInfo Export()
        {
            return new KeyInfo
            {
                PrivateKeyInfo = Key.ToDer()
            };
        }

        private byte[] GeneratePkcs10(bool requireOcspMustStaple)
        {

            var keyUsage = new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment);

            if (Key.Algorithm != KeyAlgorithm.RS256)
            {
                // Elliptic Curve keys don't support KeyEncipherment 
                keyUsage = new KeyUsage(KeyUsage.DigitalSignature);
            }

            var extensionsToAdd = new Dictionary<DerObjectIdentifier, X509Extension>();

            var x509 = new X509Name(attributes.Select(p => p.Id).ToArray(), attributes.Select(p => p.Value).ToArray());

            // If Telephone Number (TN) authorization list certificate extension required add required extension
            if (TnAuthList.Any())
            {
                attributes.Clear();

                x509 = new X509Name(attributes.Select(p => p.Id).ToArray(), attributes.Select(p => p.Value).ToArray());

                foreach (var tnAuthBytes in tnAuthList)
                {
                    extensionsToAdd.Add(new DerObjectIdentifier("1.3.6.1.5.5.7.1.26"), new X509Extension(false, new DerOctetString(tnAuthBytes)));
                }

                // CRL distribution points
                var crls = new List<DistributionPoint>();
                foreach (var crl in crlDistributionPoints)
                {
                    crls.Add(
                    new DistributionPoint(
                      new DistributionPointName(
                            new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crl.ToString()))
                            ),
                      null, null)
                    );
                };

                var crlDistPoint = new CrlDistPoint(crls.ToArray());
                extensionsToAdd.Add(X509Extensions.CrlDistributionPoints, new X509Extension(false, new DerOctetString(crlDistPoint.GetDerEncoded())));
            }
            else
            {
                if (SubjectAlternativeNames.Count == 0)
                {
                    SubjectAlternativeNames.Add(commonName);
                }

                var altNames = this.SubjectAlternativeNames
                    .Distinct()
                    .Select(n => new GeneralName(GeneralName.DnsName, n))
                    .ToArray();


                extensionsToAdd.Add(X509Extensions.BasicConstraints, new X509Extension(false, new DerOctetString(new BasicConstraints(false))));
                extensionsToAdd.Add(X509Extensions.KeyUsage, new X509Extension(false, new DerOctetString(keyUsage)));
                extensionsToAdd.Add(X509Extensions.SubjectAlternativeName, new X509Extension(false, new DerOctetString(new GeneralNames(altNames))));
            }

            if (requireOcspMustStaple)
            {
                extensionsToAdd.Add(new DerObjectIdentifier("1.3.6.1.5.5.7.1.24"), new X509Extension(false, new DerOctetString(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x05 })));
            }

            var extensions = new X509Extensions(extensionsToAdd);

            var attribute = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));

            LoadKeyPair();

            var signatureFactory = new Asn1SignatureFactory(pkcsObjectId, keyPair.Private);

            var csr = new Pkcs10CertificationRequest(signatureFactory, x509, keyPair.Public, new DerSet(attribute));

            return csr.GetDerEncoded();
        }

        private byte[] CustomCSRBuilder(Asn1SignatureFactory signatureFactory, AsymmetricKeyParameter pubKey, DerSet attributes)
        {
            var sigAlgId = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

            var pubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);

            var version = new DerInteger(0);

            var v = new Asn1EncodableVector(version, pubKeyInfo);
            v.AddOptionalTagged(false, 0, attributes);

            var asDer = new DerSequence(v);

            var bytes = asDer.GetDerEncoded();
            return bytes;
            // Generate Signature.
            //var sigBits = new DerBitString(((IBlockResult)streamCalculator.GetResult()).Collect());
        }

        private void LoadKeyPair()
        {
            var (algo, keyPair) = keyAlgorithmProvider.GetKeyPair(Key.ToDer());
            pkcsObjectId = algo.ToPkcsObjectId();
            this.keyPair = keyPair;
        }
    }
}
