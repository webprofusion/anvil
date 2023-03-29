using System.Collections.Generic;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme.Resource;

namespace Certify.ACME.Anvil.Acme
{
    /// <summary>
    /// Presents the context for ACME order operations.
    /// </summary>
    public interface IOrderContext : IResourceContext<Order>
    {
        /// <summary>
        /// Gets the authorizations for this order.
        /// </summary>
        /// <returns>
        /// The list of authorizations.
        /// </returns>
        Task<IEnumerable<IAuthorizationContext>> Authorizations();

        /// <summary>
        /// Finalizes the certificate order.
        /// </summary>
        /// <param name="csr">The CSR in DER.</param>
        /// <returns>The order finalized.</returns>
        Task<Order> Finalize(byte[] csr);

        /// <summary>
        /// Downloads the certificate chain in PEM.
        /// </summary>
        /// <param name="preferredChain">The preferred Root Certificate.</param>
        /// <returns>The certificate chain in PEM.</returns>
        Task<CertificateChain> Download(string preferredChain = null);
    }
}
