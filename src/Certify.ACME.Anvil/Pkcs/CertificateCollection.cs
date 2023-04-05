using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Certify.ACME.Anvil.Properties;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Certify.ACME.Anvil.Pkcs
{
    /// <summary>
    /// Represents a collection of X509 certificateCollection.
    /// </summary>
    public class CertificateCollection
    {
        private readonly Dictionary<X509Name, X509Certificate> certificateCollection = new Dictionary<X509Name, X509Certificate>();

        /// <summary>
        /// Adds issuer certificates.
        /// </summary>
        /// <param name="certificates">The issuer certificates.</param>
        public void Add(byte[] certificates)
        {
            var certParser = new X509CertificateParser();
            var issuers = certParser.ReadCertificates(certificates).OfType<X509Certificate>();
            foreach (var cert in issuers)
            {
                this.certificateCollection[cert.SubjectDN] = cert;
            }
        }

        /// <summary>
        /// Gets the issuers of the given certificate, recursively inspecting the issuer of each until we can't find any more issuers in our collection
        /// </summary>
        /// <param name="der">The certificate.</param>
        /// <returns>
        /// The issuers of the certificate (if any are in our collection)
        /// </returns>
        public IList<byte[]> GetIssuers(byte[] der)
        {
            var certParser = new X509CertificateParser();
            var certificate = certParser.ReadCertificate(der);

            var chain = new List<X509Certificate>();
            while (!certificate.SubjectDN.Equivalent(certificate.IssuerDN))
            {
                if (certificateCollection.TryGetValue(certificate.IssuerDN, out var issuer))
                {
                    chain.Add(issuer);
                    certificate = issuer;
                }
                else
                {
                    break;
                }
            }

            return chain.Select(cert => cert.GetEncoded()).ToArray();
        }
    }
}
