using System;
using System.Linq;
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
        /// <param name="retryCount">The number of times to retry polling.</param>
        /// <returns>The authorization validated.</returns>
        /// <exception cref="AcmeException">Thrown when the authorization status is not Valid after completion.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when retryCount is out of range</exception>
        public static async Task<Authorization> WaitForCompletionAsync(this IAuthorizationContext context, int retryCount)
        {
            if (retryCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retryCount), Properties.Strings.ErrorRetryLessThanZero);
            }

            var authorization = await context.Resource();

            while (!IsTerminalState(authorization) && retryCount > 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(context.RetryAfter > 0 ? context.RetryAfter : 3));
                authorization = await context.Resource();

                retryCount--;
            }

            if (authorization.Status != AuthorizationStatus.Valid)
            {
                throw new AcmeException(Properties.Strings.ErrorChallengeValidationFailed);
            }

            return authorization;
        }

        /// <summary>
        /// Determines whether the authorization is in a terminal state.
        /// </summary>
        /// <param name="authorization">The authorization to check.</param>
        /// <returns>True if the authorization is in a terminal state; otherwise, false.</returns>
        private static bool IsTerminalState(Authorization authorization)
            => authorization?.Status != AuthorizationStatus.Pending;
    }
}
