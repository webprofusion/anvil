using System.Collections.Generic;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme.Resource;

namespace Certify.ACME.Anvil.Acme
{
    /// <summary>
    /// Supports ACME authorization operations.
    /// </summary>
    public interface IAuthorizationContext : IResourceContext<Authorization>
    {
        /// <summary>
        /// Gets the challenges for this authorization.
        /// </summary>
        /// <returns>The list fo challenges.</returns>
        Task<IEnumerable<IChallengeContext>> Challenges();

        /// <summary>
        /// Deactivates this authzorization.
        /// </summary>
        /// <returns>
        /// The authorization deactivated.
        /// </returns>
        Task<Authorization> Deactivate();
    }
}
