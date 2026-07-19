using System;
using System.Threading;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme;

namespace Certify.ACME.Anvil
{
    /// <summary>
    /// Internal helper for polling resource contexts until reaching a terminal state.
    /// </summary>
    internal static class ResourceContextPollingHelper
    {
        /// <summary>
        /// Waits for a resource to reach a terminal state with timeout-based polling.
        /// </summary>
        /// <typeparam name="T">The resource type.</typeparam>
        /// <param name="context">The resource context.</param>
        /// <param name="timeout">The maximum time to wait for completion. Use TimeSpan.Zero to check once without retrying.</param>
        /// <param name="cancellationToken">Cancellation token to allow external cancellation of the polling operation.</param>
        /// <param name="isTerminalState">Function to determine if the resource is in a terminal state.</param>
        /// <param name="validateFinalState">Function to validate the final state and throw if invalid.</param>
        /// <returns>The resource in terminal state.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when timeout is negative.</exception>
        /// <exception cref="OperationCanceledException">Thrown when the operation is cancelled via the cancellation token.</exception>
        public static async Task<T> WaitForCompletionAsync<T>(IResourceContext<T> context, TimeSpan timeout, CancellationToken cancellationToken, Func<T, bool> isTerminalState, Action<T> validateFinalState)
        {
            if (timeout < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), Properties.Strings.ErrorRetryLessThanZero);
            }

            var resource = await context.Resource();
            var startTime = DateTime.UtcNow;
            var endTime = startTime.Add(timeout);

            while (!isTerminalState(resource) && DateTime.UtcNow < endTime)
            {
                // Check cancellation before starting new work
                cancellationToken.ThrowIfCancellationRequested();

                // Determine how long to wait
                TimeSpan delayDuration;

                if (context.NextRetry.HasValue && context.NextRetry > DateTime.UtcNow)
                {
                    // Use NextRetry if available and in the future
                    delayDuration = context.NextRetry.Value - DateTime.UtcNow;
                }
                else
                {
                    // Fall back to RetryAfter
                    delayDuration = TimeSpan.FromSeconds(context.RetryAfter > 0 ? context.RetryAfter : 3);
                }

                // Ensure we don't wait past the timeout
                var remainingTime = endTime - DateTime.UtcNow;
                if (delayDuration > remainingTime)
                {
                    delayDuration = remainingTime;
                }

                if (delayDuration > TimeSpan.Zero)
                {
                    // Cancellation during delay will throw OperationCanceledException
                    await Task.Delay(delayDuration, cancellationToken);
                }

                // Fetch the resource status
                resource = await context.Resource();
            }

            // If we're here, we either succeeded or timed out (cancellation would have thrown)
            validateFinalState(resource);
            return resource;
        }
    }
}
