using Certify.ACME.Anvil.Pkcs;

namespace Certify.ACME.Anvil.Acme
{
    /// <summary>
    /// Represents a ACME entity returned from the server with the key pair.
    /// </summary>
    /// <typeparam name="T">The entity type.</typeparam>
    /// <seealso cref="Certify.ACME.Anvil.Acme.AcmeResult{T}" />
    public class KeyedAcmeResult<T> : AcmeResult<T>
    {
        /// <summary>
        /// Gets or sets the key.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public KeyInfo Key { get; set; }
    }
}
