using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;

namespace Certify.ACME.Anvil
{
    /// <summary>
    /// Extension methods for <see cref="IAuthorizationContext"/>.
    /// </summary>
    public static class IAuthorizationContextExtensions
    {
        /// <summary>
        /// Gets the HTTP challenge.
        /// </summary>
        /// <param name="authorizationContext">The authorization context.</param>
        /// <returns>The HTTP challenge, <c>null</c> if no HTTP challenge available.</returns>
        public static Task<IChallengeContext> Http(this IAuthorizationContext authorizationContext) =>
            authorizationContext.Challenge(ChallengeTypes.Http01);

        /// <summary>
        /// Gets the DNS challenge.
        /// </summary>
        /// <param name="authorizationContext">The authorization context.</param>
        /// <returns>The DNS challenge, <c>null</c> if no DNS challenge available.</returns>
        public static Task<IChallengeContext> Dns(this IAuthorizationContext authorizationContext) =>
            authorizationContext.Challenge(ChallengeTypes.Dns01);

        /// <summary>
        /// Gets the TLS ALPN challenge.
        /// </summary>
        /// <param name="authorizationContext">The authorization context.</param>
        /// <returns>The TLS ALPN challenge, <c>null</c> if no TLS ALPN challenge available.</returns>
        public static Task<IChallengeContext> TlsAlpn(this IAuthorizationContext authorizationContext) =>
            authorizationContext.Challenge(ChallengeTypes.TlsAlpn01);

        /// <summary>
        /// Gets a challenge by type.
        /// </summary>
        /// <param name="authorizationContext">The authorization context.</param>
        /// <param name="type">The challenge type.</param>
        /// <returns>The challenge, <c>null</c> if no challenge found.</returns>
        public static async Task<IChallengeContext> Challenge(this IAuthorizationContext authorizationContext, string type)
        {
            var challenges = await authorizationContext.Challenges();
            return challenges.FirstOrDefault(c => c.Type == type);
        }

        /// <summary>
        /// Waits for the authorization to reach a terminal state (valid).
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="timeout">The maximum time to wait for completion. Use TimeSpan.Zero to check once without retrying.</param>
        /// <param name="cancellationToken">Cancellation token to allow external cancellation of the polling operation.</param>
        /// <returns>The authorization validated.</returns>
        /// <exception cref="AcmeException">Thrown when the authorization status is not Valid after completion.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when timeout is negative.</exception>
        /// <exception cref="OperationCanceledException">Thrown when the operation is cancelled.</exception>
        public static Task<Authorization> WaitForCompletionAsync(this IAuthorizationContext context, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            return ResourceContextPollingHelper.WaitForCompletionAsync(
                context,
                timeout,
                cancellationToken,
                isTerminalState: authorization => authorization?.Status != AuthorizationStatus.Pending,
                validateFinalState: authorization =>
                {
                    if (authorization.Status != AuthorizationStatus.Valid)
                    {
                        throw new AcmeException(Properties.Strings.ErrorChallengeValidationFailed);
                    }
                });
        }
    }
}
