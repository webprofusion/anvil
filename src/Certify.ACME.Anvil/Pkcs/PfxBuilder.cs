using System.Collections.Generic;
using System.IO;
using System.Linq;
using Certify.ACME.Anvil.Crypto;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Certify.ACME.Anvil.Pkcs
{
    /// <summary>
    /// Supports generating PFX from the certificate and key pair.
    /// </summary>
    public class PfxBuilder
    {
        private static readonly KeyAlgorithmProvider signatureAlgorithmProvider = new KeyAlgorithmProvider();

        private readonly X509Certificate certificate;
        private readonly IKey privateKey;
        private readonly CertificateCollection issuerCertCache = new CertificateCollection();

        /// <summary>
        /// Gets or sets a value indicating whether to include the full certificate chain in the PFX.
        /// </summary>
        /// <value>
        ///   <c>true</c> if include the full certificate chain in the PFX; otherwise, <c>false</c>.
        /// </value>
        public bool FullChain { get; set; } = true;

        /// <summary>
        /// Initializes a new instance of the <see cref="PfxBuilder"/> class.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="privateKeyInfo">The private key information.</param>
        public PfxBuilder(byte[] certificate, KeyInfo privateKeyInfo)
            : this(certificate, signatureAlgorithmProvider.GetKey(privateKeyInfo.PrivateKeyInfo))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PfxBuilder"/> class.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="privateKey">The private key.</param>
        public PfxBuilder(byte[] certificate, IKey privateKey)
        {
            var certParser = new X509CertificateParser();
            this.certificate = certParser.ReadCertificate(certificate);
            this.privateKey = privateKey;
        }

        /// <summary>
        /// Adds an issuer certificate.
        /// </summary>
        /// <param name="certificate">The issuer certificate.</param>
        public void AddIssuer(byte[] certificate) => issuerCertCache.Add(certificate);

        /// <summary>
        /// Adds issuer certificateCollection.
        /// </summary>
        /// <param name="certificates">The issuer certificateCollection.</param>
        public void AddIssuers(byte[] certificates) => issuerCertCache.Add(certificates);

        /// <summary>
        /// Builds the PFX with specified friendly name.
        /// </summary>
        /// <param name="friendlyName">The friendly name.</param>
        /// <param name="password">The password.</param>
        /// <param name="useLegacyKeyAlgorithms">If true, use default Pkcs12StoreBuilder cert and key algorithms, if false, use AES256 with SHA256 and HMAC-SHA256</param>
        /// <param name="allowBuildWithoutKnownRoot">If true, cert chain </param>
        /// <returns>The PFX data.</returns>
        public byte[] Build(string friendlyName, string password, bool useLegacyKeyAlgorithms = true, bool allowBuildWithoutKnownRoot = false)
        {
            var keyPair = LoadKeyPair();

            var builder = new Pkcs12StoreBuilder();

            builder.SetCertAlgorithm(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc);

            if (useLegacyKeyAlgorithms)
            {
                // use key algorithm most compatible with older versions of OpenSSL etc
                builder.SetKeyAlgorithm(Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc);
            }
            else
            {
                // use more modern choice of key algorithm
                builder.SetKeyAlgorithm(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdAes256Cbc, Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdHmacWithSha256);
            }

            var store = builder.Build();

            var entry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, entry);

            if (FullChain && !certificate.IssuerDN.Equivalent(certificate.SubjectDN))
            {
                var certChain = BuildCertChain(allowBuildWithoutKnownRoot);

                var certChainEntries = certChain.Select(c => new X509CertificateEntry(c)).ToList();

                store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(keyPair.Private), certChainEntries.ToArray());
            }
            else
            {
                store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(keyPair.Private), new[] { entry });
            }

            using (var buffer = new MemoryStream())
            {
                store.Save(buffer, password.ToCharArray(), new SecureRandom());
                return buffer.ToArray();
            }
        }

        /// <summary>
        /// Uses the BC PkixCertPathBuilder to build a valid certificate path from end entity to root or deepest known intermediate
        /// </summary>
        /// <param name="allowBuildWithoutKnownRoot"></param>
        /// <returns></returns>
        private IList<Org.BouncyCastle.X509.X509Certificate> BuildCertChain(bool allowBuildWithoutKnownRoot = false)
        {
            var certParser = new X509CertificateParser();

            var issuerCerts = issuerCertCache
                .GetIssuers(certificate.GetEncoded())
                .Select(der => certParser.ReadCertificate(der));

            var certificates = issuerCerts
                .Select(cert => new
                {
                    IsRoot = cert.IssuerDN.Equivalent(cert.SubjectDN),
                    Cert = cert
                });

            // ideally we build the trust chain from the real root, and roots are ones where the issuer distinguished named is also the subject distinguished named 
            var rootCerts = new HashSet<TrustAnchor>(
                certificates.Where(c => c.IsRoot)
                .Select(c => new TrustAnchor(c.Cert, null))
            );

            // other issuers in the chain are intermediates

            var endEntityAndIntermediateCerts = certificates
                .Where(c => !c.IsRoot)
                .Select(c => c.Cert)
                .ToList();

            // the PkixCertPathBuilder also requires the end entity cert in the trusts anchor set
            endEntityAndIntermediateCerts.Add(certificate);

            var target = new X509CertStoreSelector
            {
                Certificate = certificate
            };

            PkixBuilderParameters builderParams;

            // If we know the root issuer cert we can use that as the deepest part of our chain, otherwise we can only build our path up to our last known intermediate
            // If we don't know the root and have no intermediates then path building will fail

            var buildUsedIntermediateTrustAnchor = false;
            X509Certificate intermediateTrustAnchor = null;

            if (allowBuildWithoutKnownRoot && rootCerts.Count == 0)
            {
                // no matching roots known, use the best intermediate (non-root intermediate in our list which is not issued by another item in the list)

                // find intermediates closest to root, where subject is not an issuer we have in our list of intermediates
                intermediateTrustAnchor = endEntityAndIntermediateCerts
                    .Where(c => !endEntityAndIntermediateCerts.Any(i => i.SubjectDN.ToString() == c.IssuerDN.ToString()))
                    .FirstOrDefault();

                var intermediateHashSet = new HashSet<TrustAnchor>(new List<TrustAnchor> { new TrustAnchor(intermediateTrustAnchor, null) });

                builderParams = new PkixBuilderParameters(intermediateHashSet, target)
                {
                    IsRevocationEnabled = false
                };

                buildUsedIntermediateTrustAnchor = true;
            }
            else
            {
                // use a known root to build our chain
                builderParams = new PkixBuilderParameters(rootCerts, target)
                {
                    IsRevocationEnabled = false
                };

                buildUsedIntermediateTrustAnchor = false;
            }

            var store = CollectionUtilities.CreateStore<X509Certificate>(endEntityAndIntermediateCerts);
            builderParams.AddStoreCert(store);

            var builder = new PkixCertPathBuilder();

            // build and validate the certificate path
            var result = builder.Build(builderParams);

            var fullChain = result.CertPath.Certificates.Cast<Org.BouncyCastle.X509.X509Certificate>().ToList();

            if (buildUsedIntermediateTrustAnchor && intermediateTrustAnchor != null)
            {
                // include intermediate we used as trust anchor
                fullChain.Add(intermediateTrustAnchor);
            }

            return fullChain;
        }

        private AsymmetricCipherKeyPair LoadKeyPair()
        {
            var (_, keyPair) = signatureAlgorithmProvider.GetKeyPair(privateKey.ToDer());
            return keyPair;
        }
    }
}
