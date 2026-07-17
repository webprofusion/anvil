using System;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;
using Certify.ACME.Anvil.Pkcs;
using Certify.ACME.Anvil.Properties;

namespace Certify.ACME.Anvil
{
    /// <summary>
    /// Extension methods for <see cref="IOrderContext"/>.
    /// </summary>
    public static class IOrderContextExtensions
    {
        /// <summary>
        /// Finalizes the certificate order.
        /// </summary>
        /// <param name="context">The order context.</param>
        /// <param name="csr">The CSR.</param>
        /// <param name="key">The private key for the certificate.</param>
        /// <returns>
        /// The order finalized.
        /// </returns>
        public static async Task<Order> Finalize(this IOrderContext context, CsrInfo csr, IKey key)
        {
            var builder = await context.CreateCsr(key);

            foreach (var (name, value) in csr.Fields)
            {
                builder.AddName(name, value);
            }

            var csrBytes = builder.Generate(csr.RequireOcspMustStaple);
            return await context.Finalize(csrBytes);
        }

        /// <summary>
        /// Creates CSR from the order.
        /// </summary>
        /// <param name="context">The order context.</param>
        /// <param name="key">The private key.</param>
        /// <returns>The CSR.</returns>
        public static async Task<CertificationRequestBuilder> CreateCsr(this IOrderContext context, IKey key)
        {
            var builder = new CertificationRequestBuilder(key);
            var order = await context.Resource();
            foreach (var identifier in order.Identifiers)
            {
                if (identifier.Type == IdentifierType.Dns)
                {
                    builder.SubjectAlternativeNames.Add(identifier.Value);
                }
                else if (identifier.Type == IdentifierType.Ip)
                {
                    builder.IpAddresses.Add(identifier.Value);
                }
            }

            return builder;
        }

        /// <summary>
        /// Waits for the order to reach a terminal state (valid).
        /// </summary>
        /// <param name="context">The order context.</param>
        /// <param name="retryCount">The number of times to retry polling.</param>
        /// <returns>The order validated.</returns>
        /// <exception cref="AcmeException">Thrown when the order status is not Valid after completion.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when retryCount is out of range</exception>
        public static async Task<Order> WaitForCompletionAsync(this IOrderContext context, int retryCount)
        {
            if (retryCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retryCount), Strings.ErrorRetryLessThanZero);
            }
        
            var order = await context.Resource();

            while (!IsTerminalState(order) && retryCount > 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(3));
                order = await context.Resource();

                retryCount--;
            }

            if (order.Status != OrderStatus.Valid)
            {
                throw new AcmeException(Strings.ErrorFinalizeFailed);
            }

            return order;
        }

        /// <summary>
        /// Determines whether the order is in a terminal state.
        /// </summary>
        /// <param name="order">The order to check.</param>
        /// <returns>True if the order is in a terminal state; otherwise, false.</returns>
        private static bool IsTerminalState(Order order)
            => (order?.Status == OrderStatus.Valid && order?.Certificate != null) 
               || order?.Status == OrderStatus.Invalid;

        /// <summary>
        /// Finalizes and download the certificate for the order.
        /// </summary>
        /// <param name="context">The order context.</param>
        /// <param name="csr">The CSR.</param>
        /// <param name="key">The private key for the certificate.</param>
        /// <param name="retryCount">Number of retries when the Order is in 'processing' state. (default = 1)</param>
        /// <param name="preferredChain">The preferred Root Certificate.</param>
        /// <returns>
        /// The certificate generated.
        /// </returns>
        public static async Task<CertificateChain> Generate(this IOrderContext context, CsrInfo csr, IKey key, string preferredChain = null, int retryCount = 3)
        {
            var order = await context.Resource();
            if (order.Status != OrderStatus.Ready && // draft-11
                order.Status != OrderStatus.Pending) // pre draft-11
            {
                throw new AcmeException(string.Format(Strings.ErrorInvalidOrderStatusForFinalize, order.Status));
            }

            order = await context.Finalize(csr, key);

            if (order.Status != OrderStatus.Valid)
            {
                order = await context.WaitForCompletionAsync(retryCount);
            }

            return await context.Download(order, preferredChain);
        }

        /// <summary>
        /// Gets the authorization by identifier.
        /// </summary>
        /// <param name="context">The order context.</param>
        /// <param name="value">The identifier value.</param>
        /// <param name="type">The identifier type.</param>
        /// <returns>The authorization found.</returns>
        public static async Task<IAuthorizationContext> Authorization(this IOrderContext context, string value, IdentifierType type = IdentifierType.Dns)
        {
            var wildcard = value.StartsWith("*.");
            if (wildcard)
            {
                value = value.Substring(2);
            }

            foreach (var authzCtx in await context.Authorizations())
            {
                var authz = await authzCtx.Resource();
                if (string.Equals(authz.Identifier.Value, value, StringComparison.OrdinalIgnoreCase) &&
                    wildcard == authz.Wildcard.GetValueOrDefault() &&
                    authz.Identifier.Type == type)
                {
                    return authzCtx;
                }
            }

            return null;
        }
    }
}
