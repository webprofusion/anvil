using System;
using System.Threading;
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
        /// <param name="timeout">The maximum time to wait for completion. Use TimeSpan.Zero to check once without retrying.</param>
        /// <param name="cancellationToken">Cancellation token to allow external cancellation of the polling operation.</param>
        /// <returns>The order validated.</returns>
        /// <exception cref="AcmeException">Thrown when the order status is not Valid after completion.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when timeout is negative.</exception>
        /// <exception cref="OperationCanceledException">Thrown when the operation is cancelled.</exception>
        public static Task<Order> WaitForCompletionAsync(this IOrderContext context, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            return ResourceContextPollingHelper.WaitForCompletionAsync(
                context,
                timeout,
                cancellationToken,
                IsTerminalState,
                order =>
                {
                    if (order.Status != OrderStatus.Valid)
                        throw new AcmeException(Strings.ErrorFinalizeFailed);
                });
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
        /// <param name="preferredChain">The preferred Root Certificate.</param>
        /// <param name="retryCount">Number of retries when the Order is in 'processing' state. (default = 3)</param>
        /// <returns>
        /// The certificate generated.
        /// </returns>
        [Obsolete("Use Generate(context, csr, key, preferredChain, timeout, cancellationToken) instead.")]
        public static Task<CertificateChain> Generate(this IOrderContext context, CsrInfo csr, IKey key, string preferredChain = null, int retryCount = 3)
        {
            // Estimate total timeout based on inputs. Actual retries may be fewer if the order reaches a terminal state sooner.
            var estimatedTimeout = TimeSpan.FromSeconds(Math.Max(context.RetryAfter, 2) * retryCount);
            return Generate(context, csr, key, preferredChain, estimatedTimeout, CancellationToken.None);
        }

        /// <summary>
        /// Finalizes and download the certificate for the order.
        /// </summary>
        /// <param name="context">The order context.</param>
        /// <param name="csr">The CSR.</param>
        /// <param name="key">The private key for the certificate.</param>
        /// <param name="preferredChain">The preferred Root Certificate.</param>
        /// <param name="timeout">Maximum time to wait for the Order to reach 'valid' state.</param>
        /// <param name="cancellationToken">Cancellation token to allow external cancellation of the polling operation.</param>
        /// <returns>
        /// The certificate generated.
        /// </returns>
        public static async Task<CertificateChain> Generate(this IOrderContext context, CsrInfo csr, IKey key, string preferredChain, TimeSpan timeout, CancellationToken cancellationToken = default)
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
                order = await context.WaitForCompletionAsync(timeout, cancellationToken);
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
