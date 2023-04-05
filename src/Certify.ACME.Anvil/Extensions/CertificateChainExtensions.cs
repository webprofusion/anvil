using System.IO;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace Certify.ACME.Anvil
{
    /// <summary>
    /// Extension methods for <see cref="CertificateChain"/>.
    /// </summary>
    public static class CertificateChainExtensions
    {
        /// <summary>
        /// Converts the certificate to PFX with the key.
        /// </summary>
        /// <param name="certificateChain">The certificate chain.</param>
        /// <param name="certKey">The certificate private key.</param>
        /// <returns>The PFX.</returns>
        public static PfxBuilder ToPfx(this CertificateChain certificateChain, IKey certKey)
        {
            var pfx = new PfxBuilder(certificateChain.Certificate.ToDer(), certKey);
            if (certificateChain.Issuers != null)
            {
                foreach (var issuer in certificateChain.Issuers)
                {
                    pfx.AddIssuer(issuer.ToDer());
                }
            }

            return pfx;
        }

        /// <summary>
        /// Encodes the full certificate chain in PEM.
        /// </summary>
        /// <param name="certificateChain">The certificate chain.</param>
        /// <param name="certKey">The certificate key.</param>
        /// <returns>The encoded certificate chain.</returns>
        public static string ToPem(this CertificateChain certificateChain, IKey certKey = null)
        {
            var issuerCertCache = new CertificateCollection();
            foreach (var issuer in certificateChain.Issuers)
            {
                issuerCertCache.Add(issuer.ToDer());
            }

            var issuers = issuerCertCache.GetIssuers(certificateChain.Certificate.ToDer());

            using (var writer = new StringWriter())
            {
                if (certKey != null)
                {
                    writer.WriteLine(certKey.ToPem().TrimEnd());
                }

                writer.WriteLine(certificateChain.Certificate.ToPem().TrimEnd());

                var certParser = new X509CertificateParser();
                var pemWriter = new PemWriter(writer);
                foreach (var issuer in issuers)
                {
                    var cert = certParser.ReadCertificate(issuer);
                    pemWriter.WriteObject(cert);
                }

                return writer.ToString();
            }
        }
    }
}
